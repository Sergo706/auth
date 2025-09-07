import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { strangeThings } from '../../src/anomalies.js';
import { generateRefreshToken } from '../../src/refreshTokens.js';

describe('Anomalies - Canary Cookie Security', () => {
  let testUserId: number;
  let validToken: string;
  let correctCanaryId: string;

  beforeEach(async (context) => {
    testUserId = context.testUserId;
    
    // Get the correct canary ID for this user
    const [visitorRows] = await context.mainPool.execute<any[]>(
      'SELECT v.canary_id FROM visitors v JOIN users u ON v.visitor_id = u.visitor_id WHERE u.id = ?',
      [testUserId]
    );
    correctCanaryId = visitorRows[0].canary_id;

    // Generate a valid refresh token (7 days TTL)
    const tokenResult = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId);
    validToken = tokenResult.raw;
  });

  afterEach(async (context) => {
    await context.mainPool.execute('DELETE FROM refresh_tokens WHERE user_id = ?', [testUserId]);
  });

  it('should trigger MFA for mismatched canary cookie', async () => {
    const wrongCanaryId = 'wrong-canary-id-123';
    
    const result = await strangeThings(
      validToken,
      wrongCanaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('new device');
    expect(result.reqMFA).toBe(true);
    expect(result.userId).toBe(testUserId);
    expect(result.visitorId).toBeDefined();
  });

  it('should trigger MFA for empty canary cookie', async () => {
    const result = await strangeThings(
      validToken,
      '',
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('new device');
    expect(result.reqMFA).toBe(true);
  });

  it('should trigger MFA for null/undefined canary cookie', async () => {
    const result = await strangeThings(
      validToken,
      null as any,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('new device');
    expect(result.reqMFA).toBe(true);
  });

  it('should handle potential canary cookie injection attacks', async () => {
    const maliciousCanaries = [
      "'; DROP TABLE visitors; --",
      "' OR '1'='1",
      "'; UPDATE visitors SET canary_id = 'hacked'; --",
      correctCanaryId + "'; DELETE FROM users; --"
    ];

    for (const maliciousCanary of maliciousCanaries) {
      const result = await strangeThings(
        validToken,
        maliciousCanary,
        '127.0.0.1',
        'Mozilla/5.0 (Test Browser)',
        false
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('new device');
      expect(result.reqMFA).toBe(true);
    }
  });

  it('should accept correct canary cookie', async () => {
    const result = await strangeThings(
      validToken,
      correctCanaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    // Should pass canary check but may fail other checks
    expect(result.reason).not.toBe('new device');
    expect(result.userId).toBe(testUserId);
  });

  it('should be case sensitive for canary cookie', async () => {
    const upperCaseCanary = correctCanaryId.toUpperCase();
    
    if (upperCaseCanary !== correctCanaryId) {
      const result = await strangeThings(
        validToken,
        upperCaseCanary,
        '127.0.0.1',
        'Mozilla/5.0 (Test Browser)',
        false
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('new device');
      expect(result.reqMFA).toBe(true);
    }
  });

  it('should detect canary cookie with extra characters', async () => {
    const modifiedCanary = correctCanaryId + 'extra';
    
    const result = await strangeThings(
      validToken,
      modifiedCanary,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('new device');
    expect(result.reqMFA).toBe(true);
  });

  it('should detect partial canary cookie', async () => {
    const partialCanary = correctCanaryId.substring(0, correctCanaryId.length - 1);
    
    const result = await strangeThings(
      validToken,
      partialCanary,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('new device');
    expect(result.reqMFA).toBe(true);
  });

  it('should handle very long canary cookie strings', async () => {
    const longCanary = 'a'.repeat(1000);
    
    const result = await strangeThings(
      validToken,
      longCanary,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('new device');
    expect(result.reqMFA).toBe(true);
  });

  it('should handle canary cookie with special characters', async () => {
    const specialCanary = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    const result = await strangeThings(
      validToken,
      specialCanary,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('new device');
    expect(result.reqMFA).toBe(true);
  });
});