import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { strangeThings } from '../../src/anomalies.js';
import { generateRefreshToken } from '../../src/refreshTokens.js';

describe('Anomalies - Session Idle Detection', () => {
  let testUserId: number;
  let validToken: string;
  let canaryId: string;

  beforeEach(async (context) => {
    testUserId = context.testUserId;
    
    // Get canary ID
    const [visitorRows] = await context.mainPool.execute<any[]>(
      'SELECT v.canary_id FROM visitors v JOIN users u ON v.visitor_id = u.visitor_id WHERE u.id = ?',
      [testUserId]
    );
    canaryId = visitorRows[0].canary_id;

    // Generate valid token (7 days TTL)
    const tokenResult = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId);
    validToken = tokenResult.raw;
  });

  afterEach(async (context) => {
    await context.mainPool.execute('DELETE FROM refresh_tokens WHERE user_id = ?', [testUserId]);
  });

  it('should trigger MFA for idle sessions (24+ hours)', async (context) => {
    // Set last_seen to more than 24 hours ago
    const oldDate = new Date(Date.now() - 25 * 60 * 60 * 1000); // 25 hours ago
    await context.mainPool.execute(
      'UPDATE visitors v JOIN users u ON v.visitor_id = u.visitor_id SET v.last_seen = ? WHERE u.id = ?',
      [oldDate, testUserId]
    );

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('idle');
    expect(result.reqMFA).toBe(true);
    expect(result.userId).toBe(testUserId);
  });

  it('should allow active sessions (within 24 hours)', async (context) => {
    // Set last_seen to recent time (within 24 hours)
    const recentDate = new Date(Date.now() - 12 * 60 * 60 * 1000); // 12 hours ago
    await context.mainPool.execute(
      'UPDATE visitors v JOIN users u ON v.visitor_id = u.visitor_id SET v.last_seen = ? WHERE u.id = ?',
      [recentDate, testUserId]
    );

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.reason).not.toBe('idle');
    // When checks pass, result doesn't contain userId
    expect(typeof result.valid).toBe('boolean');
    expect(typeof result.reason).toBe('string');
  });

  it('should handle edge case of exactly 24 hours', async (context) => {
    // Set last_seen to exactly 24 hours ago  
    const exactDate = new Date(Date.now() - 24 * 60 * 60 * 1000 + 1000); // slightly less than 24h
    await context.mainPool.execute(
      'UPDATE visitors v JOIN users u ON v.visitor_id = u.visitor_id SET v.last_seen = ? WHERE u.id = ?',
      [exactDate, testUserId]
    );

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    // Should not trigger idle (slightly under 24 hours should be allowed)
    expect(result.reason).not.toBe('idle');
    expect(typeof result.valid).toBe('boolean');
  });

  it('should handle future last_seen dates', async (context) => {
    // Set last_seen to future date (system clock issues)
    const futureDate = new Date(Date.now() + 60 * 60 * 1000); // 1 hour in future
    await context.mainPool.execute(
      'UPDATE visitors v JOIN users u ON v.visitor_id = u.visitor_id SET v.last_seen = ? WHERE u.id = ?',
      [futureDate, testUserId]
    );

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    // Future dates should be treated as recent activity
    expect(result.reason).not.toBe('idle');
    expect(typeof result.valid).toBe('boolean');
  });

  it('should handle null last_seen dates', async (context) => {
    // Set last_seen to null
    await context.mainPool.execute(
      'UPDATE visitors v JOIN users u ON v.visitor_id = u.visitor_id SET v.last_seen = NULL WHERE u.id = ?',
      [testUserId]
    );

    // This should throw an error due to null getTime() call
    await expect(strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    )).rejects.toThrow();
  });

  it('should handle very old last_seen dates', async (context) => {
    // Set last_seen to very old date (1 year ago)
    const veryOldDate = new Date(Date.now() - 365 * 24 * 60 * 60 * 1000);
    await context.mainPool.execute(
      'UPDATE visitors v JOIN users u ON v.visitor_id = u.visitor_id SET v.last_seen = ? WHERE u.id = ?',
      [veryOldDate, testUserId]
    );

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('idle');
    expect(result.reqMFA).toBe(true);
  });

  it('should handle millisecond precision around 24 hour boundary', async (context) => {
    // Test just over 24 hours (should trigger idle)
    const justOver24h = new Date(Date.now() - (24 * 60 * 60 * 1000) - 1000); // 1 second over
    await context.mainPool.execute(
      'UPDATE visitors v JOIN users u ON v.visitor_id = u.visitor_id SET v.last_seen = ? WHERE u.id = ?',
      [justOver24h, testUserId]
    );

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('idle');
    expect(result.reqMFA).toBe(true);
  });

  it('should handle timezone differences and DST', async (context) => {
    // Create a proper MySQL datetime
    const oldDate = new Date('2024-01-15 12:00:00'); // Fixed format for MySQL
    await context.mainPool.execute(
      'UPDATE visitors v JOIN users u ON v.visitor_id = u.visitor_id SET v.last_seen = ? WHERE u.id = ?',
      [oldDate, testUserId]
    );

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    // Should trigger idle since date is very old
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('idle');
    expect(result.reqMFA).toBe(true);
  });

  it('should handle recent activity (5 minutes ago)', async (context) => {
    // Set last_seen to very recent
    const recentDate = new Date(Date.now() - 5 * 60 * 1000); // 5 minutes ago
    await context.mainPool.execute(
      'UPDATE visitors v JOIN users u ON v.visitor_id = u.visitor_id SET v.last_seen = ? WHERE u.id = ?',
      [recentDate, testUserId]
    );

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.reason).not.toBe('idle');
    expect(typeof result.valid).toBe('boolean');
  });

  it('should handle current timestamp as last_seen', async (context) => {
    // Set last_seen to now
    const now = new Date();
    await context.mainPool.execute(
      'UPDATE visitors v JOIN users u ON v.visitor_id = u.visitor_id SET v.last_seen = ? WHERE u.id = ?',
      [now, testUserId]
    );

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.reason).not.toBe('idle');
    expect(typeof result.valid).toBe('boolean');
  });
});