import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { strangeThings } from '../../src/anomalies.js';
import { generateRefreshToken } from '../../src/refreshTokens.js';

describe('Anomalies - Session Limits and Rate Limiting', () => {
  let testUserId: number;
  let anotherUserId: number;
  let canaryId: string;

  beforeEach(async (context) => {
    testUserId = context.testUserId;
    anotherUserId = context.anotherUserId;
    
    // Get canary ID for main test user
    const [visitorRows] = await context.mainPool.execute<any[]>(
      'SELECT v.canary_id FROM visitors v JOIN users u ON v.visitor_id = u.visitor_id WHERE u.id = ?',
      [testUserId]
    );
    canaryId = visitorRows[0].canary_id;
  });

  afterEach(async (context) => {
    // Clean up all tokens for both users
    await context.mainPool.execute('DELETE FROM refresh_tokens WHERE user_id IN (?, ?)', [testUserId, anotherUserId]);
  });

  it('should trigger MFA when user exceeds maximum allowed sessions', async (context) => {
    // Create maximum allowed sessions (5 as per config) + 1 more
    const tokens = [];
    for (let i = 0; i < 6; i++) {
      tokens.push((await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId)).raw);
    }

    // Test with the last token - should trigger session limit
    const result = await strangeThings(
      tokens[5],
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('more than 5 active sessions');
    expect(result.reqMFA).toBe(true);
    expect(result.userId).toBe(testUserId);
  });

  it('should allow sessions within the limit', async () => {
    // Create only 3 sessions (within limit of 5)
    const tokens = [];
    for (let i = 0; i < 3; i++) {
      tokens.push((await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId)).raw);
    }

    const result = await strangeThings(
      tokens[2],
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    // Should not fail due to session limits
    expect(result.reason).not.toBe('more than 5 active sessions');
    expect(result.userId).toBe(testUserId);
  });

  it('should block and revoke token when creating 4+ tokens in 10 minutes', async (context) => {
    // Create 4 refresh tokens quickly
    const tokens = [];
    for (let i = 0; i < 4; i++) {
      tokens.push((await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId)).raw);
    }

    // The 4th token should trigger rate limiting
    const result = await strangeThings(
      tokens[3],
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('3 tokens in less than 10 min');
    expect(result.reqMFA).toBe(false); // Hard block, not MFA
    
    // Verify the token was revoked
    const [tokenCheck] = await context.mainPool.execute<any[]>(
      'SELECT valid FROM refresh_tokens WHERE token = ?',
      [require('crypto').createHash('sha256').update(tokens[3]).digest('hex')]
    );
    expect(tokenCheck[0].valid).toBe(0); // Should be revoked
  });

  it('should handle rate limiting correctly across different users', async () => {
    // Create multiple tokens for first user
    for (let i = 0; i < 4; i++) {
      await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId);
    }

    // Create token for second user - should not be affected by first user's rate limit
    const secondUserToken = (await generateRefreshToken(7 * 24 * 60 * 60 * 1000, anotherUserId)).raw;
    
    const [visitorRows] = await context.mainPool.execute<any[]>(
      'SELECT v.canary_id FROM visitors v JOIN users u ON v.visitor_id = u.visitor_id WHERE u.id = ?',
      [anotherUserId]
    );
    const secondUserCanary = visitorRows[0].canary_id;

    const result = await strangeThings(
      secondUserToken,
      secondUserCanary,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    // Second user should not be affected by first user's rate limit
    expect(result.reason).not.toBe('3 tokens in less than 10 min');
    expect(result.userId).toBe(anotherUserId);
  });

  it('should bypass session limits with recent MFA', async (context) => {
    // Set recent MFA time (within bypass period)
    const now = new Date();
    await context.mainPool.execute(
      'UPDATE users SET last_mfa_at = ? WHERE id = ?',
      [now, testUserId]
    );

    // Create more than the allowed sessions
    const tokens = [];
    for (let i = 0; i < 6; i++) {
      tokens.push((await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId)).raw);
    }

    const result = await strangeThings(
      tokens[5],
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    // Should bypass session limit due to recent MFA
    expect(result.reason).not.toBe('more than 5 active sessions');
    expect(result.userId).toBe(testUserId);
  });

  it('should not bypass session limits with old MFA', async (context) => {
    // Set old MFA time (beyond bypass period - more than 24 hours ago)
    const oldDate = new Date(Date.now() - 25 * 60 * 60 * 1000); // 25 hours ago
    await context.mainPool.execute(
      'UPDATE users SET last_mfa_at = ? WHERE id = ?',
      [oldDate, testUserId]
    );

    // Create more than allowed sessions
    const tokens = [];
    for (let i = 0; i < 6; i++) {
      tokens.push((await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId)).raw);
    }

    const result = await strangeThings(
      tokens[5],
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    // Should trigger session limit since MFA is too old
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('more than 5 active sessions');
    expect(result.reqMFA).toBe(true);
  });

  it('should handle edge case of exactly 3 recent tokens', async () => {
    // Create exactly 3 tokens (at the threshold)
    const tokens = [];
    for (let i = 0; i < 3; i++) {
      tokens.push((await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId)).raw);
    }

    const result = await strangeThings(
      tokens[2],
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    // Should not trigger rate limiting yet
    expect(result.reason).not.toBe('3 tokens in less than 10 min');
    expect(result.userId).toBe(testUserId);
  });

  it('should handle concurrent token creation and validation', async () => {
    // Create tokens concurrently
    const promises = Array(3).fill(0).map(() => generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId));
    const tokenResults = await Promise.all(promises);
    const tokens = tokenResults.map(result => result.raw);

    // Test all tokens concurrently
    const validationPromises = tokens.map(token =>
      strangeThings(token, canaryId, '127.0.0.1', 'Mozilla/5.0 (Test Browser)', false)
    );

    const results = await Promise.all(validationPromises);
    
    // All should have valid user IDs
    results.forEach(result => {
      expect(result.userId).toBe(testUserId);
    });
  });
});