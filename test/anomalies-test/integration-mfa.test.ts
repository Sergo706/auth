// @vitest-environment node

/**
 * @vitest-environment-options { "sequential": true }
 */

import { describe, expect, it, afterEach } from "vitest";
import { strangeThings } from "../../src/anomalies.js";
import { verifyMFA } from "../../src/jwtAuth/middleware/verifyEmailMFA.js";
import { generateRefreshToken } from "../../src/refreshTokens.js";
import mysql2 from 'mysql2/promise';
import crypto from 'crypto';
import { Request, Response } from 'express';

describe('Integration Tests - Anomalies + MFA Flow', () => {

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
      get: (header: string) => header === 'User-Agent' ? fingerPrint.userAgent : undefined,
      newVisitorId: undefined
    } as any;
  }

  function createMockResponse(): Response {
    const res = {
      statusCode: 200,
      jsonData: null,
      cookiesSet: [] as any[],
      status: function(code: number) { this.statusCode = code; return this; },
      json: function(data: any) { this.jsonData = data; return this; },
      cookie: function(name: string, value: any, options: any) { 
        this.cookiesSet.push({ name, value, options }); 
        return this; 
      },
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

  it('should detect suspicious activity and trigger MFA requirement', async (context) => {
    // Create user with high suspicious activity score
    const testData = await createTestVisitorAndUser(context, {
      suspicos_activity_score: 10 // Above threshold
    });
    
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    // Step 1: Anomaly detection should flag this as suspicious
    const anomalyResult = await strangeThings(
      refreshToken.raw,
      testData.canaryId,
      testData.ip_address,
      testData.user_agent,
      false
    );

    expect(anomalyResult.valid).toBe(false);
    expect(anomalyResult.reason).toBe('Suspicos score to high');
    expect(anomalyResult.reqMFA).toBe(true);
    expect(anomalyResult.userId).toBe(testData.userId);
    expect(anomalyResult.visitorId).toBe(testData.visitorId);

    // Step 2: User should be required to complete MFA
    const jti = crypto.randomUUID();
    await createMFACode(context, testData.userId, jti, '1234567');

    const mfaReq = createMockRequest(
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

    const mfaRes = createMockResponse();
    const next = (): void => {};

    await verifyMFA(mfaReq, mfaRes, next);

    expect(mfaRes.statusCode).toBe(200);
    expect(mfaRes.jsonData).toHaveProperty('accessToken');

    // Step 3: After successful MFA, suspicious activity should be reset/allowed
    const [userCheck] = await context.mainPool.execute<mysql2.RowDataPacket[]>(
      'SELECT last_mfa_at FROM users WHERE id = ?',
      [testData.userId]
    );
    expect(userCheck[0].last_mfa_at).toBeTruthy();
  });

  it('should handle device change detection and MFA workflow', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    // Step 1: Detect device change (different canary cookie)
    const anomalyResult = await strangeThings(
      refreshToken.raw,
      'different-canary-id', // Different device
      testData.ip_address,
      testData.user_agent,
      false
    );

    expect(anomalyResult.valid).toBe(false);
    expect(anomalyResult.reason).toBe('new device');
    expect(anomalyResult.reqMFA).toBe(true);

    // Step 2: Complete MFA verification for new device
    const jti = crypto.randomUUID();
    await createMFACode(context, testData.userId, jti, '7654321');

    const mfaReq = createMockRequest(
      { code: '7654321' },
      { purpose: 'MFA', subject: 'MAGIC_LINK_MFA_CHECKS', jti, visitor: testData.visitorId },
      {
        userAgent: testData.user_agent,
        ipAddress: testData.ip_address,
        country: testData.country,
        city: testData.city,
        device: testData.device_type,
        browser: testData.browser
      },
      { canary_id: 'different-canary-id' }
    );

    const mfaRes = createMockResponse();
    const next = (): void => {};

    await verifyMFA(mfaReq, mfaRes, next);

    expect(mfaRes.statusCode).toBe(200);
    expect(mfaRes.jsonData).toHaveProperty('accessToken');

    // Step 3: Verify new device permissions were granted
    const [visitorCheck] = await context.mainPool.execute<mysql2.RowDataPacket[]>(
      'SELECT proxy_allowed, hosting_allowed FROM visitors WHERE visitor_id = ?',
      [testData.visitorId]
    );
    expect(visitorCheck[0].proxy_allowed).toBe(1);
    expect(visitorCheck[0].hosting_allowed).toBe(1);
  });

  it('should handle geographic location changes with MFA', async (context) => {
    const testData = await createTestVisitorAndUser(context, {
      ip_address: '192.168.1.100'
    });
    
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    // Step 1: Detect IP/location change
    const anomalyResult = await strangeThings(
      refreshToken.raw,
      testData.canaryId,
      '10.0.0.1', // Different IP range
      testData.user_agent,
      false
    );

    expect(anomalyResult.valid).toBe(false);
    expect(anomalyResult.reason).toBe('Ip does not match');
    expect(anomalyResult.reqMFA).toBe(true);

    // Step 2: MFA should succeed and update location info
    const jti = crypto.randomUUID();
    await createMFACode(context, testData.userId, jti, '9876543');

    const mfaReq = createMockRequest(
      { code: '9876543' },
      { purpose: 'MFA', subject: 'MAGIC_LINK_MFA_CHECKS', jti, visitor: testData.visitorId },
      {
        userAgent: testData.user_agent,
        ipAddress: '10.0.0.1', // New IP
        country: 'CA', // New country
        city: 'Toronto',
        device: testData.device_type,
        browser: testData.browser
      },
      { canary_id: testData.canaryId },
      '10.0.0.1'
    );

    const mfaRes = createMockResponse();
    const next = (): void => {};

    await verifyMFA(mfaReq, mfaRes, next);

    expect(mfaRes.statusCode).toBe(200);
    expect(mfaRes.jsonData).toHaveProperty('accessToken');
  });

  it('should handle session limit violations with MFA bypass', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    
    // Create multiple sessions (exceeding limit)
    const tokens = [];
    for (let i = 0; i < 6; i++) {
      const token = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);
      tokens.push(token);
    }

    // Step 1: Should detect session limit violation
    const anomalyResult = await strangeThings(
      tokens[5].raw,
      testData.canaryId,
      testData.ip_address,
      testData.user_agent,
      false
    );

    expect(anomalyResult.valid).toBe(false);
    expect(anomalyResult.reason).toBe('more than 5 active sessions');
    expect(anomalyResult.reqMFA).toBe(true);

    // Step 2: Complete MFA to authorize additional session
    const jti = crypto.randomUUID();
    await createMFACode(context, testData.userId, jti, '5555555');

    const mfaReq = createMockRequest(
      { code: '5555555' },
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

    const mfaRes = createMockResponse();
    const next = (): void => {};

    await verifyMFA(mfaReq, mfaRes, next);

    expect(mfaRes.statusCode).toBe(200);

    // Step 3: After MFA, future sessions should bypass limit for a period
    const newToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);
    
    const postMfaResult = await strangeThings(
      newToken.raw,
      testData.canaryId,
      testData.ip_address,
      testData.user_agent,
      false
    );

    // Should now pass due to recent MFA
    expect(postMfaResult.valid).toBe(true);
    expect(postMfaResult.reason).toBe('Checks passed');
    expect(postMfaResult.reqMFA).toBe(false);
  });

  it('should handle rapid token creation with proper security flow', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    
    // Create multiple tokens rapidly
    const now = new Date();
    const recentTime = new Date(now.getTime() - 5 * 60 * 1000); // 5 minutes ago
    
    for (let i = 0; i < 4; i++) {
      await context.mainPool.execute(
        'INSERT INTO refresh_tokens (user_id, token, valid, expiresAt, created_at, usage_count) VALUES (?, ?, ?, ?, ?, ?)',
        [testData.userId, crypto.randomBytes(32).toString('hex'), true, new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), recentTime, 0]
      );
    }

    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    // Should detect rapid token creation and block
    const anomalyResult = await strangeThings(
      refreshToken.raw,
      testData.canaryId,
      testData.ip_address,
      testData.user_agent,
      false
    );

    expect(anomalyResult.valid).toBe(false);
    expect(anomalyResult.reason).toBe('3 tokens in less than 10 min');
    expect(anomalyResult.reqMFA).toBe(false); // No MFA for this violation, just block

    // Verify token was revoked
    const [tokenCheck] = await context.mainPool.execute<mysql2.RowDataPacket[]>(
      'SELECT valid FROM refresh_tokens WHERE token = ?',
      [crypto.createHash('sha256').update(refreshToken.raw).digest('hex')]
    );
    
    expect(tokenCheck[0].valid).toBe(false);
  });

  it('should handle idle session detection with MFA requirement', async (context) => {
    const twoDaysAgo = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000);
    const testData = await createTestVisitorAndUser(context, {
      last_seen: twoDaysAgo
    });
    
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    // Step 1: Detect idle session
    const anomalyResult = await strangeThings(
      refreshToken.raw,
      testData.canaryId,
      testData.ip_address,
      testData.user_agent,
      false
    );

    expect(anomalyResult.valid).toBe(false);
    expect(anomalyResult.reason).toBe('idle');
    expect(anomalyResult.reqMFA).toBe(true);

    // Step 2: Complete MFA to reactivate session
    const jti = crypto.randomUUID();
    await createMFACode(context, testData.userId, jti, '1111111');

    const mfaReq = createMockRequest(
      { code: '1111111' },
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

    const mfaRes = createMockResponse();
    const next = (): void => {};

    await verifyMFA(mfaReq, mfaRes, next);

    expect(mfaRes.statusCode).toBe(200);
    expect(mfaRes.jsonData).toHaveProperty('accessToken');

    // Step 3: Verify session is now active
    const [visitorUpdate] = await context.mainPool.execute<mysql2.RowDataPacket[]>(
      'SELECT last_seen FROM visitors WHERE visitor_id = ?',
      [testData.visitorId]
    );
    // last_seen should be updated through the MFA process
    expect(new Date(visitorUpdate[0].last_seen).getTime()).toBeGreaterThan(twoDaysAgo.getTime());
  });

  it('should handle complete attack scenario with proper security responses', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    // Step 1: Multiple suspicious indicators
    const testScenarios = [
      {
        description: 'Wrong cookie + high suspicious score',
        visitorUpdate: { suspicos_activity_score: 10 },
        testParams: {
          cookie: 'malicious-canary',
          ip: testData.ip_address,
          ua: testData.user_agent
        },
        expectedReason: 'Suspicos score to high'
      },
      {
        description: 'Different IP + wrong device fingerprint',
        visitorUpdate: { suspicos_activity_score: 0 },
        testParams: {
          cookie: testData.canaryId,
          ip: '8.8.8.8',
          ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)'
        },
        expectedReason: 'Ip does not match'
      }
    ];

    for (const scenario of testScenarios) {
      // Update visitor data for this scenario
      await context.mainPool.execute(
        'UPDATE visitors SET suspicos_activity_score = ? WHERE visitor_id = ?',
        [scenario.visitorUpdate.suspicos_activity_score, testData.visitorId]
      );

      // Test anomaly detection
      const anomalyResult = await strangeThings(
        refreshToken.raw,
        scenario.testParams.cookie,
        scenario.testParams.ip,
        scenario.testParams.ua,
        false
      );

      expect(anomalyResult.valid).toBe(false);
      expect(anomalyResult.reason).toBe(scenario.expectedReason);
      expect(anomalyResult.reqMFA).toBe(true);

      // Attempt MFA with correct code
      const jti = crypto.randomUUID();
      await createMFACode(context, testData.userId, jti, '2222222');

      const mfaReq = createMockRequest(
        { code: '2222222' },
        { purpose: 'MFA', subject: 'MAGIC_LINK_MFA_CHECKS', jti, visitor: testData.visitorId },
        {
          userAgent: scenario.testParams.ua,
          ipAddress: scenario.testParams.ip,
          country: 'US',
          city: 'New York',
          device: 'mobile',
          browser: 'Safari'
        },
        { canary_id: scenario.testParams.cookie }
      );

      const mfaRes = createMockResponse();
      const next = (): void => {};

      await verifyMFA(mfaReq, mfaRes, next);

      expect(mfaRes.statusCode).toBe(200);
      expect(mfaRes.jsonData).toHaveProperty('accessToken');

      // Clean up for next scenario
      await context.mainPool.execute('DELETE FROM mfa_codes WHERE user_id = ?', [testData.userId]);
    }
  });

});