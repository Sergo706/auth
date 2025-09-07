// @vitest-environment node

/**
 * @vitest-environment-options { "sequential": true }
 */

import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { strangeThings } from "../../src/anomalies.js";
import { generateRefreshToken } from "../../src/refreshTokens.js";
import mysql2 from 'mysql2/promise';
import crypto from 'crypto';

describe('Anomalies Security Tests - Token Validation', () => {

  // Test helper to create test data
  async function createTestVisitorAndUser(context: any, visitorData = {}) {
    const canaryId = `test-canary-${Date.now()}-${Math.random()}`;
    const defaultVisitorData = {
      canary_id: canaryId,
      ip_address: '192.168.1.100',
      user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      country: 'US',
      city: 'New York',
      district: 'Manhattan',
      lat: '40.7128',
      lon: '-74.0060',
      timezone: 'America/New_York',
      currency: 'USD',
      isp: 'Test ISP',
      org: 'Test Org',
      as_org: 'Test AS',
      device_type: 'desktop',
      browser: 'Chrome',
      proxy: false,
      proxy_allowed: false,
      hosting: false,
      hosting_allowed: false,
      last_seen: new Date(),
      deviceVendor: 'Intel',
      deviceModel: 'Unknown',
      browserType: 'browser',
      browserVersion: '119.0',
      os: 'Windows',
      suspicos_activity_score: 0,
      ...visitorData
    };

    const [visitorResult] = await context.mainPool.execute<mysql2.ResultSetHeader>(
      `INSERT INTO visitors (${Object.keys(defaultVisitorData).join(', ')}) VALUES (${Object.keys(defaultVisitorData).map(() => '?').join(', ')})`,
      Object.values(defaultVisitorData)
    );

    const visitorId = visitorResult.insertId;

    const [userResult] = await context.mainPool.execute<mysql2.ResultSetHeader>(
      'INSERT INTO users (email, password_hash, visitor_id, last_mfa_at) VALUES (?, ?, ?, ?)',
      [`test-${Date.now()}@example.com`, 'test-hash', visitorId, new Date()]
    );

    return {
      userId: userResult.insertId,
      visitorId,
      canaryId,
      ...defaultVisitorData
    };
  }

  afterEach(async (context) => {
    // Clean up test data
    await context.mainPool.execute('DELETE FROM refresh_tokens WHERE user_id IN (SELECT id FROM users WHERE email LIKE "test-%")');
    await context.mainPool.execute('DELETE FROM users WHERE email LIKE "test-%"');
    await context.mainPool.execute('DELETE FROM visitors WHERE canary_id LIKE "test-canary-%"');
  });

  it('should reject completely invalid token formats', async (context) => {
    const invalidTokens = [
      '',
      'invalid-token',
      null,
      undefined,
      'a'.repeat(1000), // Very long token
      '<script>alert("xss")</script>',
      '../../etc/passwd',
      'SELECT * FROM users;'
    ];

    for (const invalidToken of invalidTokens) {
      const result = await strangeThings(
        invalidToken as string,
        'test-canary',
        '192.168.1.100',
        'Mozilla/5.0 Test',
        false
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('No token found');
      expect(result.reqMFA).toBe(false);
      expect(result.userId).toBeUndefined();
      expect(result.visitorId).toBeUndefined();
    }
  });

  it('should handle non-existent token gracefully', async (context) => {
    const nonExistentToken = crypto.randomBytes(32).toString('hex');
    
    const result = await strangeThings(
      nonExistentToken,
      'test-canary',
      '192.168.1.100',
      'Mozilla/5.0 Test',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('No token found');
    expect(result.reqMFA).toBe(false);
    expect(result.userId).toBeUndefined();
    expect(result.visitorId).toBeUndefined();
  });

  it('should reject invalid tokens that exist in database', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    // Manually invalidate the token
    await context.mainPool.execute(
      'UPDATE refresh_tokens SET valid = FALSE WHERE token = ?',
      [crypto.createHash('sha256').update(refreshToken.raw).digest('hex')]
    );

    const result = await strangeThings(
      refreshToken.raw,
      testData.canaryId,
      testData.ip_address,
      testData.user_agent,
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('token is invalid or being used more then ones');
    expect(result.reqMFA).toBe(false);
  });

  it('should detect token reuse after rotation', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    // Simulate token usage by incrementing usage count
    await context.mainPool.execute(
      'UPDATE refresh_tokens SET usage_count = 1 WHERE token = ?',
      [crypto.createHash('sha256').update(refreshToken.raw).digest('hex')]
    );

    const result = await strangeThings(
      refreshToken.raw,
      testData.canaryId,
      testData.ip_address,
      testData.user_agent,
      true // rotated = true
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('token is invalid or being used more then ones');
    expect(result.reqMFA).toBe(false);

    // Verify token was revoked
    const [tokenCheck] = await context.mainPool.execute<mysql2.RowDataPacket[]>(
      'SELECT valid FROM refresh_tokens WHERE token = ?',
      [crypto.createHash('sha256').update(refreshToken.raw).digest('hex')]
    );
    
    expect(tokenCheck[0].valid).toBe(false);
  });

  it('should handle expired tokens correctly', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    
    // Create an expired token
    const hashedToken = crypto.randomBytes(32).toString('hex');
    const expiredDate = new Date(Date.now() - 24 * 60 * 60 * 1000); // 24 hours ago

    await context.mainPool.execute(
      'INSERT INTO refresh_tokens (user_id, token, valid, expiresAt, usage_count) VALUES (?, ?, ?, ?, ?)',
      [testData.userId, hashedToken, true, expiredDate, 0]
    );

    const rawToken = crypto.randomBytes(32).toString('hex');
    
    const result = await strangeThings(
      rawToken,
      testData.canaryId,
      testData.ip_address,
      testData.user_agent,
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('No token found');
    expect(result.reqMFA).toBe(false);
  });

  it('should handle SQL injection attempts safely', async (context) => {
    const sqlInjectionAttempts = [
      "'; DROP TABLE refresh_tokens; --",
      "' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35 --",
      "' OR '1'='1",
      "'; DELETE FROM users; --",
      "' UNION SELECT password_hash FROM users --"
    ];

    for (const injectionAttempt of sqlInjectionAttempts) {
      const result = await strangeThings(
        injectionAttempt,
        'test-canary',
        '192.168.1.100',
        'Mozilla/5.0 Test',
        false
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('No token found');
      expect(result.reqMFA).toBe(false);
      
      // Verify tables still exist and contain expected data
      const [tableCheck] = await context.mainPool.execute('SHOW TABLES LIKE "refresh_tokens"');
      expect(tableCheck).toHaveLength(1);
    }
  });

  it('should handle concurrent token validation attempts', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    // Create multiple concurrent validation attempts
    const concurrentValidations = Array.from({ length: 10 }, () =>
      strangeThings(
        refreshToken.raw,
        testData.canaryId,
        testData.ip_address,
        testData.user_agent,
        false
      )
    );

    const results = await Promise.all(concurrentValidations);

    // All results should be consistent
    const firstResult = results[0];
    results.forEach(result => {
      expect(result.valid).toBe(firstResult.valid);
      expect(result.reason).toBe(firstResult.reason);
      expect(result.reqMFA).toBe(firstResult.reqMFA);
    });
  });

  it('should handle database connection failures gracefully', async (context) => {
    // Close the connection temporarily to simulate connection failure
    const originalExecute = context.mainPool.execute;
    context.mainPool.execute = async () => {
      throw new Error('Database connection failed');
    };

    try {
      await expect(strangeThings(
        'test-token',
        'test-canary',
        '192.168.1.100',
        'Mozilla/5.0 Test',
        false
      )).rejects.toThrow('Database connection failed');
    } finally {
      // Restore the original function
      context.mainPool.execute = originalExecute;
    }
  });

});