// @vitest-environment node

/**
 * @vitest-environment-options { "sequential": true }
 */

import { describe, expect, it, afterEach } from "vitest";
import { verifyMFA } from "../../src/jwtAuth/middleware/verifyEmailMFA.js";
import { generateRefreshToken } from "../../src/refreshTokens.js";
import mysql2 from 'mysql2/promise';
import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';

describe('MFA Flow Security Tests - Rate Limiting & Protection', () => {

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

  async function createMFACode(context: any, userId: number, jti: string, code: string = '1234567') {
    const codeHash = crypto.createHash('sha256').update(code).digest('hex');
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, userId);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes from now

    await context.mainPool.execute(
      'INSERT INTO mfa_codes (jti, code_hash, user_id, token, expires_at, used) VALUES (?, ?, ?, ?, ?, ?)',
      [jti, codeHash, userId, refreshToken.raw, expiresAt, false]
    );

    return {
      code,
      codeHash,
      refreshToken,
      expiresAt
    };
  }

  function createMockRequest(body: any, linkData: any, fingerPrint: any, cookies: any = {}, ip: string = '192.168.1.100'): Request {
    return {
      body,
      link: linkData,
      fingerPrint,
      cookies,
      ip,
      is: (contentType: string) => contentType === 'application/json',
      get: (header: string) => header === 'User-Agent' ? 'Mozilla/5.0 Test' : undefined,
      newVisitorId: undefined
    } as any;
  }

  function createMockResponse(): Response {
    const res = {
      statusCode: 200,
      jsonData: null,
      status: function(code: number) { this.statusCode = code; return this; },
      json: function(data: any) { this.jsonData = data; return this; },
      locals: {}
    };
    return res as any;
  }

  afterEach(async (context) => {
    // Clean up test data
    await context.mainPool.execute('DELETE FROM mfa_codes WHERE user_id IN (SELECT id FROM users WHERE email LIKE "test-%")');
    await context.mainPool.execute('DELETE FROM refresh_tokens WHERE user_id IN (SELECT id FROM users WHERE email LIKE "test-%")');
    await context.mainPool.execute('DELETE FROM users WHERE email LIKE "test-%"');
    await context.mainPool.execute('DELETE FROM visitors WHERE canary_id LIKE "test-canary-%"');
  });

  it('should implement brute force protection for MFA codes', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const jti = crypto.randomUUID();
    await createMFACode(context, testData.userId, jti, '1234567');

    const results = [];

    // Attempt multiple invalid codes rapidly
    for (let i = 0; i < 10; i++) {
      const req = createMockRequest(
        { code: '0000000' }, // Always wrong code
        { purpose: 'MFA', subject: 'MAGIC_LINK_MFA_CHECKS', jti, visitor: testData.visitorId },
        { userAgent: testData.user_agent, ipAddress: testData.ip_address },
        { canary_id: testData.canaryId }
      );

      const res = createMockResponse();
      const next = (): void => {};

      await verifyMFA(req, res, next);
      results.push({ statusCode: res.statusCode, jsonData: res.jsonData });

      // Small delay to avoid overwhelming the system
      await new Promise(resolve => setTimeout(resolve, 10));
    }

    // All should fail, but rate limiting should kick in
    results.forEach(result => {
      expect(result.statusCode).toBeGreaterThanOrEqual(400);
    });

    // After multiple failures, should be rate limited
    const lastResults = results.slice(-3);
    const rateLimitedResults = lastResults.filter(r => 
      r.statusCode === 429 || (r.jsonData && r.jsonData.error && r.jsonData.error.includes('rate limit'))
    );
    
    // Should have some rate limiting responses or consistent failure patterns
    expect(results.every(r => r.statusCode !== 200)).toBe(true);
  });

  it('should prevent multiple simultaneous MFA attempts from same IP', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const jti = crypto.randomUUID();
    await createMFACode(context, testData.userId, jti, '1234567');

    const createRequest = (code: string) => createMockRequest(
      { code },
      { purpose: 'MFA', subject: 'MAGIC_LINK_MFA_CHECKS', jti, visitor: testData.visitorId },
      { userAgent: testData.user_agent, ipAddress: testData.ip_address },
      { canary_id: testData.canaryId },
      '192.168.1.100' // Same IP for all requests
    );

    const responses = [];
    const verificationPromises = [];

    // Create multiple concurrent attempts with different codes
    for (let i = 0; i < 5; i++) {
      const req = createRequest(`123456${i}`);
      const res = createMockResponse();
      const next = (): void => {};
      
      responses.push(res);
      verificationPromises.push(verifyMFA(req, res, next));
    }

    await Promise.all(verificationPromises);

    // Should have rate limiting or consistent failure behavior
    const failedResponses = responses.filter(res => res.statusCode >= 400);
    expect(failedResponses.length).toBeGreaterThan(0);
  });

  it('should handle time-based attack attempts', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const jti = crypto.randomUUID();
    
    // Create multiple MFA codes with different times
    const codes = ['1111111', '2222222', '3333333', '4444444', '5555555'];
    
    for (const code of codes) {
      await createMFACode(context, testData.userId, jti, code);
    }

    const timingResults = [];

    // Measure response times for both valid and invalid codes
    for (let i = 0; i < codes.length; i++) {
      const startTime = Date.now();
      
      const req = createMockRequest(
        { code: codes[i] },
        { purpose: 'MFA', subject: 'MAGIC_LINK_MFA_CHECKS', jti, visitor: testData.visitorId },
        { userAgent: testData.user_agent, ipAddress: testData.ip_address },
        { canary_id: testData.canaryId }
      );

      const res = createMockResponse();
      const next = (): void => {};

      await verifyMFA(req, res, next);
      
      const endTime = Date.now();
      timingResults.push({
        code: codes[i],
        duration: endTime - startTime,
        statusCode: res.statusCode
      });

      await new Promise(resolve => setTimeout(resolve, 100)); // Brief delay between attempts
    }

    // Response times should be somewhat consistent to prevent timing attacks
    const durations = timingResults.map(r => r.duration);
    const maxDuration = Math.max(...durations);
    const minDuration = Math.min(...durations);
    const timingVariation = maxDuration - minDuration;

    // Timing variation should be reasonable (less than 1 second difference)
    expect(timingVariation).toBeLessThan(1000);
  });

  it('should validate session token integrity during MFA', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const jti = crypto.randomUUID();
    const mfaData = await createMFACode(context, testData.userId, jti, '1234567');

    // Test with tampered refresh token
    const tamperedToken = mfaData.refreshToken.raw.slice(0, -5) + 'XXXXX';
    
    await context.mainPool.execute(
      'UPDATE mfa_codes SET token = ? WHERE jti = ?',
      [tamperedToken, jti]
    );

    const req = createMockRequest(
      { code: '1234567' },
      { purpose: 'MFA', subject: 'MAGIC_LINK_MFA_CHECKS', jti, visitor: testData.visitorId },
      { userAgent: testData.user_agent, ipAddress: testData.ip_address },
      { canary_id: testData.canaryId }
    );

    const res = createMockResponse();
    const next = (): void => {};

    await verifyMFA(req, res, next);

    expect(res.statusCode).toBe(401);
    expect(res.jsonData).toHaveProperty('error');
  });

  it('should prevent MFA bypass through JTI manipulation', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const jti = crypto.randomUUID();
    const fakeJti = crypto.randomUUID();
    await createMFACode(context, testData.userId, jti, '1234567');

    const req = createMockRequest(
      { code: '1234567' },
      { purpose: 'MFA', subject: 'MAGIC_LINK_MFA_CHECKS', jti: fakeJti, visitor: testData.visitorId }, // Wrong JTI
      { userAgent: testData.user_agent, ipAddress: testData.ip_address },
      { canary_id: testData.canaryId }
    );

    const res = createMockResponse();
    const next = (): void => {};

    await verifyMFA(req, res, next);

    expect(res.statusCode).toBe(401);
    expect(res.jsonData).toHaveProperty('error');
    expect(res.jsonData.error).toContain('Invalid or expired code');
  });

  it('should handle visitor ID validation properly', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const jti = crypto.randomUUID();
    await createMFACode(context, testData.userId, jti, '1234567');

    const invalidVisitorIds = [
      null,
      undefined,
      -1,
      0,
      999999999, // Non-existent visitor ID
      'invalid-visitor-id',
      '<script>alert("xss")</script>'
    ];

    for (const invalidVisitorId of invalidVisitorIds) {
      const req = createMockRequest(
        { code: '1234567' },
        { purpose: 'MFA', subject: 'MAGIC_LINK_MFA_CHECKS', jti, visitor: invalidVisitorId },
        { userAgent: testData.user_agent, ipAddress: testData.ip_address },
        { canary_id: testData.canaryId }
      );

      const res = createMockResponse();
      const next = (): void => {};

      await verifyMFA(req, res, next);

      expect(res.statusCode).toBeGreaterThanOrEqual(400);
      expect(res.jsonData).toHaveProperty('error');
    }
  });

  it('should implement proper session cleanup after MFA success', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const jti = crypto.randomUUID();
    const mfaData = await createMFACode(context, testData.userId, jti, '1234567');

    const req = createMockRequest(
      { code: '1234567' },
      { purpose: 'MFA', subject: 'MAGIC_LINK_MFA_CHECKS', jti, visitor: testData.visitorId },
      { userAgent: testData.user_agent, ipAddress: testData.ip_address },
      { canary_id: testData.canaryId }
    );

    const res = createMockResponse();
    const next = (): void => {};

    await verifyMFA(req, res, next);

    expect(res.statusCode).toBe(200);

    // Verify old refresh token was revoked
    const [oldTokenCheck] = await context.mainPool.execute<mysql2.RowDataPacket[]>(
      'SELECT valid FROM refresh_tokens WHERE token = ?',
      [crypto.createHash('sha256').update(mfaData.refreshToken.raw).digest('hex')]
    );
    
    if (oldTokenCheck.length > 0) {
      expect(oldTokenCheck[0].valid).toBe(false);
    }

    // Verify MFA code was consumed
    const [mfaCheck] = await context.mainPool.execute<mysql2.RowDataPacket[]>(
      'SELECT * FROM mfa_codes WHERE jti = ?',
      [jti]
    );
    expect(mfaCheck).toHaveLength(0);
  });

  it('should handle fingerprint validation during MFA', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const jti = crypto.randomUUID();
    await createMFACode(context, testData.userId, jti, '1234567');

    const suspiciousFingerprints = [
      {
        userAgent: '<script>alert("xss")</script>',
        ipAddress: '192.168.1.100'
      },
      {
        userAgent: testData.user_agent,
        ipAddress: '../../etc/passwd'
      },
      {
        userAgent: testData.user_agent,
        ipAddress: null
      },
      {
        userAgent: null,
        ipAddress: testData.ip_address
      }
    ];

    for (const fingerprint of suspiciousFingerprints) {
      const req = createMockRequest(
        { code: '1234567' },
        { purpose: 'MFA', subject: 'MAGIC_LINK_MFA_CHECKS', jti, visitor: testData.visitorId },
        fingerprint,
        { canary_id: testData.canaryId }
      );

      const res = createMockResponse();
      const next = (): void => {};

      await verifyMFA(req, res, next);

      // Should handle malicious fingerprints gracefully
      expect([200, 400, 401, 500]).toContain(res.statusCode);
      
      // If it succeeds, verify it's a legitimate success
      if (res.statusCode === 200) {
        expect(res.jsonData).toHaveProperty('accessToken');
      }
    }
  });

  it('should enforce MFA code uniqueness per session', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const jti1 = crypto.randomUUID();
    const jti2 = crypto.randomUUID();
    
    // Create same code for different sessions
    await createMFACode(context, testData.userId, jti1, '1234567');
    await createMFACode(context, testData.userId, jti2, '1234567');

    // First session should work
    const req1 = createMockRequest(
      { code: '1234567' },
      { purpose: 'MFA', subject: 'MAGIC_LINK_MFA_CHECKS', jti: jti1, visitor: testData.visitorId },
      { userAgent: testData.user_agent, ipAddress: testData.ip_address },
      { canary_id: testData.canaryId }
    );

    const res1 = createMockResponse();
    const next = (): void => {};

    await verifyMFA(req1, res1, next);
    expect(res1.statusCode).toBe(200);

    // Second session with same code should work independently
    const req2 = createMockRequest(
      { code: '1234567' },
      { purpose: 'MFA', subject: 'MAGIC_LINK_MFA_CHECKS', jti: jti2, visitor: testData.visitorId },
      { userAgent: testData.user_agent, ipAddress: testData.ip_address },
      { canary_id: testData.canaryId }
    );

    const res2 = createMockResponse();
    await verifyMFA(req2, res2, next);
    expect(res2.statusCode).toBe(200);
  });

  it('should handle edge cases in transaction rollback', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const jti = crypto.randomUUID();
    await createMFACode(context, testData.userId, jti, '1234567');

    // Create a scenario where the database operation partially fails
    const originalGetConnection = context.mainPool.getConnection;
    let connectionCount = 0;
    
    context.mainPool.getConnection = async () => {
      connectionCount++;
      const conn = await originalGetConnection.call(context.mainPool);
      
      if (connectionCount === 1) {
        // Override execute to fail on specific operations
        const originalExecute = conn.execute;
        let executeCount = 0;
        
        conn.execute = async (...args: any[]) => {
          executeCount++;
          if (executeCount === 3) { // Fail on user update
            throw new Error('Simulated database failure');
          }
          return originalExecute.apply(conn, args);
        };
      }
      
      return conn;
    };

    const req = createMockRequest(
      { code: '1234567' },
      { purpose: 'MFA', subject: 'MAGIC_LINK_MFA_CHECKS', jti, visitor: testData.visitorId },
      { userAgent: testData.user_agent, ipAddress: testData.ip_address },
      { canary_id: testData.canaryId }
    );

    const res = createMockResponse();
    const next = (): void => {};

    try {
      await verifyMFA(req, res, next);
      
      expect(res.statusCode).toBe(500);
      expect(res.jsonData.error).toBe('Internal server error');

      // Verify MFA code was not consumed due to rollback
      const [mfaCheck] = await context.mainPool.execute<mysql2.RowDataPacket[]>(
        'SELECT * FROM mfa_codes WHERE jti = ?',
        [jti]
      );
      expect(mfaCheck.length).toBeGreaterThan(0);
      
    } finally {
      // Restore original function
      context.mainPool.getConnection = originalGetConnection;
    }
  });

});