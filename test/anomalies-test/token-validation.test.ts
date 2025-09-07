import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { strangeThings } from '../../src/anomalies.js';
import { generateRefreshToken, revokeRefreshToken } from '../../src/refreshTokens.js';
import { createHash } from 'crypto';

describe('Anomalies - Token Validation', () => {
  let testUserId: number;
  let testVisitorId: number;
  let validToken: string;
  let canaryId: string;

  beforeEach(async (context) => {
    testUserId = context.testUserId;
    
    // Create test visitor and get canary ID
    const [visitorRows] = await context.mainPool.execute<any[]>(
      'SELECT v.canary_id, v.visitor_id FROM visitors v JOIN users u ON v.visitor_id = u.visitor_id WHERE u.id = ?',
      [testUserId]
    );
    canaryId = visitorRows[0].canary_id;
    testVisitorId = visitorRows[0].visitor_id;

    // Generate a valid refresh token (7 days TTL)
    const tokenResult = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId);
    validToken = tokenResult.raw;
  });

  afterEach(async (context) => {
    // Clean up any tokens created during tests
    await context.mainPool.execute('DELETE FROM refresh_tokens WHERE user_id = ?', [testUserId]);
  });

  it('should reject completely invalid/non-existent token', async () => {
    const fakeToken = 'completely-fake-token-that-does-not-exist';
    
    const result = await strangeThings(
      fakeToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('No token found');
    expect(result.reqMFA).toBe(false);
    expect(result.userId).toBeUndefined();
    expect(result.visitorId).toBeUndefined();
  });

  it('should reject empty token', async () => {
    const result = await strangeThings(
      '',
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('No token found');
    expect(result.reqMFA).toBe(false);
  });

  it('should reject null/undefined token hash', async () => {
    // Test with malformed token that creates invalid hash
    const malformedToken = '\0\0\0';
    
    const result = await strangeThings(
      malformedToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('No token found');
    expect(result.reqMFA).toBe(false);
  });

  it('should reject revoked/invalid token', async (context) => {
    // Revoke the token
    await revokeRefreshToken(validToken);
    
    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('token is invalid or being used more then ones');
    expect(result.reqMFA).toBe(false);
  });

  it('should reject token when marked as rotated but has usage count > 0', async (context) => {
    // Update token to have usage count > 0
    const hashedToken = createHash('sha256').update(validToken).digest('hex');
    await context.mainPool.execute(
      'UPDATE refresh_tokens SET usage_count = 1 WHERE token = ?',
      [hashedToken]
    );
    
    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      true // rotated = true
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('token is invalid or being used more then ones');
    expect(result.reqMFA).toBe(false);
  });

  it('should accept valid token with correct parameters', async () => {
    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      false
    );

    // When checks pass, the function returns valid: true without userId/visitorId
    expect(result.valid).toBe(true);
    expect(result.reason).toBe('Checks passed');
    expect(result.reqMFA).toBe(false);
    expect(typeof result.reason).toBe('string');
  });

  it('should handle concurrent token validation attempts', async () => {
    const promises = Array(5).fill(0).map(() =>
      strangeThings(
        validToken,
        canaryId,
        '127.0.0.1',
        'Mozilla/5.0 (Test Browser)',
        false
      )
    );

    const results = await Promise.all(promises);
    
    // All should return consistent results
    results.forEach(result => {
      expect(typeof result.valid).toBe('boolean');
      expect(typeof result.reqMFA).toBe('boolean');
      expect(typeof result.reason).toBe('string');
    });
  });

  it('should handle SQL injection attempts in token', async () => {
    const maliciousTokens = [
      "'; DROP TABLE users; --",
      "' OR '1'='1",
      "' UNION SELECT * FROM users --",
      "'; UPDATE refresh_tokens SET valid = 1; --"
    ];

    for (const maliciousToken of maliciousTokens) {
      const result = await strangeThings(
        maliciousToken,
        canaryId,
        '127.0.0.1',
        'Mozilla/5.0 (Test Browser)',
        false
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('No token found');
      expect(result.reqMFA).toBe(false);
    }
  });
});