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

describe('MFA Flow Security Tests - Code Verification', () => {

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

  function createMockRequest(body: any, linkData: any, fingerPrint: any, cookies: any = {}): Request {
    return {
      body,
      link: linkData,
      fingerPrint,
      cookies,
      ip: '192.168.1.100',
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

  it('should successfully verify valid MFA code', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const jti = crypto.randomUUID();
    const mfaData = await createMFACode(context, testData.userId, jti, '1234567');

    const req = createMockRequest(
      { code: '1234567' },
      { purpose: 'MFA', subject: 'MAGIC_LINK_MFA_CHECKS', jti, visitor: testData.visitorId },
      {
        userAgent: testData.user_agent,
        ipAddress: testData.ip_address,
        country: testData.country,
        city: testData.city,
        device: testData.device_type,
        browser: testData.browser
      },
      { canary_id: testData.canaryId }
    );

    const res = createMockResponse();
    const next = (): void => {};

    await verifyMFA(req, res, next);

    expect(res.statusCode).toBe(200);
    expect(res.jsonData).toHaveProperty('accessToken');
    expect(res.jsonData).toHaveProperty('accessIat');

    // Verify MFA code was consumed
    const [mfaCheck] = await context.mainPool.execute<mysql2.RowDataPacket[]>(
      'SELECT * FROM mfa_codes WHERE jti = ?',
      [jti]
    );
    expect(mfaCheck).toHaveLength(0); // Should be deleted

    // Verify user's last MFA timestamp was updated
    const [userCheck] = await context.mainPool.execute<mysql2.RowDataPacket[]>(
      'SELECT last_mfa_at FROM users WHERE id = ?',
      [testData.userId]
    );
    expect(userCheck[0].last_mfa_at).toBeTruthy();
  });

  it('should reject invalid MFA codes', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const jti = crypto.randomUUID();
    await createMFACode(context, testData.userId, jti, '1234567');

    const invalidCodes = [
      '0000000',
      '1234568', // Wrong code
      'abcdefg',
      '',
      null,
      undefined,
      '12345678', // Too long
      '123456', // Too short
      '<script>alert("xss")</script>',
      "'; DROP TABLE mfa_codes; --"
    ];

    for (const invalidCode of invalidCodes) {
      const req = createMockRequest(
        { code: invalidCode },
        { purpose: 'MFA', subject: 'MAGIC_LINK_MFA_CHECKS', jti, visitor: testData.visitorId },
        { userAgent: testData.user_agent, ipAddress: testData.ip_address },
        { canary_id: testData.canaryId }
      );

      const res = createMockResponse();
      const next = (): void => {};

      await verifyMFA(req, res, next);

      expect(res.statusCode).toBe(401);
      expect(res.jsonData).toHaveProperty('error');
      expect(res.jsonData.error).toContain('Invalid or expired code');
    }
  });

  it('should reject expired MFA codes', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const jti = crypto.randomUUID();
    const code = '1234567';
    const codeHash = crypto.createHash('sha256').update(code).digest('hex');
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);
    const expiredDate = new Date(Date.now() - 60 * 1000); // 1 minute ago

    await context.mainPool.execute(
      'INSERT INTO mfa_codes (jti, code_hash, user_id, token, expires_at, used) VALUES (?, ?, ?, ?, ?, ?)',
      [jti, codeHash, testData.userId, refreshToken.raw, expiredDate, false]
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
    expect(res.jsonData.error).toContain('Invalid or expired code');
  });

  it('should prevent code reuse', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const jti = crypto.randomUUID();
    const mfaData = await createMFACode(context, testData.userId, jti, '1234567');

    const req = createMockRequest(
      { code: '1234567' },
      { purpose: 'MFA', subject: 'MAGIC_LINK_MFA_CHECKS', jti, visitor: testData.visitorId },
      { userAgent: testData.user_agent, ipAddress: testData.ip_address },
      { canary_id: testData.canaryId }
    );

    const res1 = createMockResponse();
    const next = (): void => {};

    // First verification should succeed
    await verifyMFA(req, res1, next);
    expect(res1.statusCode).toBe(200);

    // Create a new MFA code entry for second attempt
    await createMFACode(context, testData.userId, jti, '1234567');

    // Second verification with same code should fail
    const res2 = createMockResponse();
    await verifyMFA(req, res2, next);
    expect(res2.statusCode).toBe(401);
    expect(res2.jsonData.error).toContain('Invalid or expired code');
  });

  it('should reject requests with wrong content type', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const jti = crypto.randomUUID();

    const req = createMockRequest(
      { code: '1234567' },
      { purpose: 'MFA', subject: 'MAGIC_LINK_MFA_CHECKS', jti, visitor: testData.visitorId },
      { userAgent: testData.user_agent, ipAddress: testData.ip_address },
      { canary_id: testData.canaryId }
    );

    // Override the is method to return false
    req.is = () => false;

    const res = createMockResponse();
    const next = (): void => {};

    await verifyMFA(req, res, next);

    expect(res.statusCode).toBe(400);
    expect(res.jsonData).toHaveProperty('error');
    expect(res.jsonData.error).toBe('Bad Request.');
  });

  it('should reject invalid link purposes', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const jti = crypto.randomUUID();

    const invalidPurposes = [
      { purpose: 'INVALID', subject: 'MAGIC_LINK_MFA_CHECKS' },
      { purpose: 'MFA', subject: 'INVALID_SUBJECT' },
      { purpose: null, subject: 'MAGIC_LINK_MFA_CHECKS' },
      { purpose: 'MFA', subject: null }
    ];

    for (const linkData of invalidPurposes) {
      const req = createMockRequest(
        { code: '1234567' },
        { ...linkData, jti, visitor: testData.visitorId },
        { userAgent: testData.user_agent, ipAddress: testData.ip_address },
        { canary_id: testData.canaryId }
      );

      const res = createMockResponse();
      const next = (): void => {};

      await verifyMFA(req, res, next);

      expect(res.statusCode).toBe(400);
      expect(res.jsonData).toHaveProperty('error');
      expect(res.jsonData.error).toBe('Invalid link purpose');
    }
  });

  it('should handle concurrent MFA verification attempts', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const jti = crypto.randomUUID();
    const mfaData = await createMFACode(context, testData.userId, jti, '1234567');

    const createRequest = () => createMockRequest(
      { code: '1234567' },
      { purpose: 'MFA', subject: 'MAGIC_LINK_MFA_CHECKS', jti, visitor: testData.visitorId },
      { userAgent: testData.user_agent, ipAddress: testData.ip_address },
      { canary_id: testData.canaryId }
    );

    const responses = [];
    const verificationPromises = [];

    // Create 5 concurrent verification attempts
    for (let i = 0; i < 5; i++) {
      const req = createRequest();
      const res = createMockResponse();
      const next = (): void => {};
      
      responses.push(res);
      verificationPromises.push(verifyMFA(req, res, next));
    }

    await Promise.all(verificationPromises);

    // Only one should succeed, others should fail
    const successfulResponses = responses.filter(res => res.statusCode === 200);
    const failedResponses = responses.filter(res => res.statusCode !== 200);

    expect(successfulResponses).toHaveLength(1);
    expect(failedResponses).toHaveLength(4);

    failedResponses.forEach(res => {
      expect(res.jsonData.error).toContain('Invalid or expired code');
    });
  });

  it('should handle database transaction failures gracefully', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const jti = crypto.randomUUID();
    const mfaData = await createMFACode(context, testData.userId, jti, '1234567');

    // Temporarily break the database connection
    const originalExecute = context.mainPool.execute;
    let executeCallCount = 0;
    
    context.mainPool.execute = async (...args: any[]) => {
      executeCallCount++;
      if (executeCallCount === 2) { // Fail on the second execute call (the DELETE)
        throw new Error('Database connection failed');
      }
      return originalExecute.apply(context.mainPool, args);
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
      expect(res.jsonData).toHaveProperty('error');
      expect(res.jsonData.error).toBe('Internal server error');
    } finally {
      // Restore the original function
      context.mainPool.execute = originalExecute;
    }
  });

  it('should validate code format properly', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const jti = crypto.randomUUID();

    const invalidFormats = [
      { code: '123456' }, // Too short
      { code: '12345678' }, // Too long
      { code: 'abcdefg' }, // Non-numeric
      { code: '123 567' }, // Contains space
      { code: '123-567' }, // Contains dash
      { code: '1234567.' }, // Contains period
      { code: '+1234567' }, // Starts with plus
      { code: '1234567a' }, // Ends with letter
    ];

    for (const testCase of invalidFormats) {
      const req = createMockRequest(
        testCase,
        { purpose: 'MFA', subject: 'MAGIC_LINK_MFA_CHECKS', jti, visitor: testData.visitorId },
        { userAgent: testData.user_agent, ipAddress: testData.ip_address },
        { canary_id: testData.canaryId }
      );

      const res = createMockResponse();
      const next = (): void => {};

      await verifyMFA(req, res, next);

      expect(res.statusCode).toBe(400);
      expect(res.jsonData).toHaveProperty('error');
      expect(res.jsonData.error).toMatch(/Invalid or expired code|Bad Request/);
    }
  });

});