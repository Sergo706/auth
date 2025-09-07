// @vitest-environment node

/**
 * @vitest-environment-options { "sequential": true }
 */

import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { strangeThings } from "../../src/anomalies.js";
import { generateRefreshToken } from "../../src/refreshTokens.js";
import mysql2 from 'mysql2/promise';
import crypto from 'crypto';

describe('Anomalies Security Tests - Device & Cookie Security', () => {

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

  it('should detect cookie mismatch and require MFA', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    const result = await strangeThings(
      refreshToken.raw,
      'different-canary-id', // Mismatched cookie
      testData.ip_address,
      testData.user_agent,
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('new device');
    expect(result.reqMFA).toBe(true);
    expect(result.userId).toBe(testData.userId);
    expect(result.visitorId).toBe(testData.visitorId);
  });

  it('should handle malicious cookie values safely', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    const maliciousCookies = [
      '<script>alert("xss")</script>',
      '../../etc/passwd',
      "'; DROP TABLE visitors; --",
      'javascript:alert(1)',
      null,
      undefined,
      'a'.repeat(10000), // Very long cookie
      String.fromCharCode(0, 1, 2, 3), // Control characters
    ];

    for (const maliciousCookie of maliciousCookies) {
      const result = await strangeThings(
        refreshToken.raw,
        maliciousCookie as string,
        testData.ip_address,
        testData.user_agent,
        false
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('new device');
      expect(result.reqMFA).toBe(true);
      expect(result.userId).toBe(testData.userId);
      expect(result.visitorId).toBe(testData.visitorId);
    }
  });

  it('should detect idle sessions and require MFA', async (context) => {
    const twoDaysAgo = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000);
    const testData = await createTestVisitorAndUser(context, {
      last_seen: twoDaysAgo
    });
    
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    const result = await strangeThings(
      refreshToken.raw,
      testData.canaryId,
      testData.ip_address,
      testData.user_agent,
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('idle');
    expect(result.reqMFA).toBe(true);
    expect(result.userId).toBe(testData.userId);
    expect(result.visitorId).toBe(testData.visitorId);
  });

  it('should accept recent sessions without MFA', async (context) => {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    const testData = await createTestVisitorAndUser(context, {
      last_seen: oneHourAgo
    });
    
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    const result = await strangeThings(
      refreshToken.raw,
      testData.canaryId,
      testData.ip_address,
      testData.user_agent,
      false
    );

    // Should pass initial checks and go to further validation
    expect(result.valid).toBe(true);
    expect(result.reason).toBe('Checks passed');
    expect(result.reqMFA).toBe(false);
  });

  it('should detect suspicious activity score and require MFA', async (context) => {
    const testData = await createTestVisitorAndUser(context, {
      suspicos_activity_score: 10 // Above threshold of 9
    });
    
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    const result = await strangeThings(
      refreshToken.raw,
      testData.canaryId,
      testData.ip_address,
      testData.user_agent,
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Suspicos score to high');
    expect(result.reqMFA).toBe(true);
    expect(result.userId).toBe(testData.userId);
    expect(result.visitorId).toBe(testData.visitorId);
  });

  it('should allow safe activity scores', async (context) => {
    const testData = await createTestVisitorAndUser(context, {
      suspicos_activity_score: 5 // Below threshold of 9
    });
    
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    const result = await strangeThings(
      refreshToken.raw,
      testData.canaryId,
      testData.ip_address,
      testData.user_agent,
      false
    );

    // Should pass and continue to further checks
    expect(result.valid).toBe(true);
    expect(result.reason).toBe('Checks passed');
    expect(result.reqMFA).toBe(false);
  });

  it('should detect device fingerprint changes', async (context) => {
    const testData = await createTestVisitorAndUser(context, {
      deviceVendor: 'Apple',
      deviceModel: 'MacBook Pro',
      browserType: 'browser',
      browserVersion: '118.0',
      os: 'macOS'
    });
    
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    // Simulate request from different device characteristics
    const result = await strangeThings(
      refreshToken.raw,
      testData.canaryId,
      testData.ip_address,
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36', // Different user agent
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Loop detected');
    expect(result.reqMFA).toBe(true);
    expect(result.userId).toBe(testData.userId);
    expect(result.visitorId).toBe(testData.visitorId);
  });

  it('should handle edge case with unknown device characteristics', async (context) => {
    const testData = await createTestVisitorAndUser(context, {
      deviceVendor: 'unknown',
      deviceModel: 'unknown',
      browserType: 'unknown',
      browserVersion: 'unknown',
      os: 'unknown'
    });
    
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    const result = await strangeThings(
      refreshToken.raw,
      testData.canaryId,
      testData.ip_address,
      testData.user_agent,
      false
    );

    // Should pass since unknown values are filtered out
    expect(result.valid).toBe(true);
    expect(result.reason).toBe('Checks passed');
    expect(result.reqMFA).toBe(false);
  });

  it('should detect session limit violations', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    
    // Create multiple valid tokens (exceeding the limit of 5)
    const tokens = [];
    for (let i = 0; i < 6; i++) {
      const token = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);
      tokens.push(token);
    }

    const result = await strangeThings(
      tokens[5].raw, // Test the 6th token
      testData.canaryId,
      testData.ip_address,
      testData.user_agent,
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('more than 5 active sessions');
    expect(result.reqMFA).toBe(true);
    expect(result.userId).toBe(testData.userId);
    expect(result.visitorId).toBe(testData.visitorId);
  });

  it('should bypass session limits for recently MFA-verified users', async (context) => {
    const recentMfaTime = new Date(Date.now() - 30 * 60 * 1000); // 30 minutes ago
    
    // Update user with recent MFA
    const testData = await createTestVisitorAndUser(context);
    await context.mainPool.execute(
      'UPDATE users SET last_mfa_at = ? WHERE id = ?',
      [recentMfaTime, testData.userId]
    );
    
    // Create multiple valid tokens (exceeding the limit of 5)
    const tokens = [];
    for (let i = 0; i < 6; i++) {
      const token = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);
      tokens.push(token);
    }

    const result = await strangeThings(
      tokens[5].raw, // Test the 6th token
      testData.canaryId,
      testData.ip_address,
      testData.user_agent,
      false
    );

    // Should pass due to recent MFA
    expect(result.valid).toBe(true);
    expect(result.reason).toBe('Checks passed');
    expect(result.reqMFA).toBe(false);
  });

  it('should detect rapid token creation attempts', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    
    // Create multiple tokens rapidly (4 tokens in less than 10 minutes)
    const now = new Date();
    const recentTime = new Date(now.getTime() - 5 * 60 * 1000); // 5 minutes ago
    
    for (let i = 0; i < 4; i++) {
      await context.mainPool.execute(
        'INSERT INTO refresh_tokens (user_id, token, valid, expiresAt, created_at, usage_count) VALUES (?, ?, ?, ?, ?, ?)',
        [testData.userId, crypto.randomBytes(32).toString('hex'), true, new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), recentTime, 0]
      );
    }

    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    const result = await strangeThings(
      refreshToken.raw,
      testData.canaryId,
      testData.ip_address,
      testData.user_agent,
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('3 tokens in less than 10 min');
    expect(result.reqMFA).toBe(false);

    // Verify the token was revoked
    const [tokenCheck] = await context.mainPool.execute<mysql2.RowDataPacket[]>(
      'SELECT valid FROM refresh_tokens WHERE token = ?',
      [crypto.createHash('sha256').update(refreshToken.raw).digest('hex')]
    );
    
    expect(tokenCheck[0].valid).toBe(false);
  });

  it('should handle timestamp edge cases correctly', async (context) => {
    // Test with exactly 24 hours idle time (boundary condition)
    const exactlyOneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const testData = await createTestVisitorAndUser(context, {
      last_seen: exactlyOneDayAgo
    });
    
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    const result = await strangeThings(
      refreshToken.raw,
      testData.canaryId,
      testData.ip_address,
      testData.user_agent,
      false
    );

    // Should be considered idle at exactly 24 hours
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('idle');
    expect(result.reqMFA).toBe(true);
  });

});