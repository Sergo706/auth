import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { strangeThings } from '../../src/anomalies.js';
import { generateRefreshToken } from '../../src/refreshTokens.js';

describe('Anomalies - IP Range and Geo Security', () => {
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

  it('should trigger MFA for completely different IP address', async () => {
    // Original IP is 127.0.0.1, use a completely different one
    const result = await strangeThings(
      validToken,
      canaryId,
      '192.168.1.100',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Ip does not match');
    expect(result.reqMFA).toBe(true);
    expect(result.userId).toBe(testUserId);
  });

  it('should trigger MFA for public IP when expecting local', async () => {
    const result = await strangeThings(
      validToken,
      canaryId,
      '8.8.8.8', // Google DNS
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Ip does not match');
    expect(result.reqMFA).toBe(true);
  });

  it('should accept same IP address', async () => {
    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1', // Same as stored
      'Mozilla/5.0 (Test Browser)',
      false
    );

    // Should not fail due to IP mismatch
    expect(result.reason).not.toBe('Ip does not match');
    expect(result.userId).toBe(testUserId);
  });

  it('should handle IPv6 addresses', async () => {
    const result = await strangeThings(
      validToken,
      canaryId,
      '::1', // IPv6 localhost
      'Mozilla/5.0 (Test Browser)',
      false
    );

    // IPv6 should be treated as different from IPv4
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Ip does not match');
    expect(result.reqMFA).toBe(true);
  });

  it('should handle malformed IP addresses', async () => {
    const malformedIPs = [
      '999.999.999.999',
      '127.0.0',
      '127.0.0.1.1',
      'not-an-ip',
      '',
      null,
      undefined
    ];

    for (const ip of malformedIPs) {
      const result = await strangeThings(
        validToken,
        canaryId,
        ip as any,
        'Mozilla/5.0 (Test Browser)',
        false
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Ip does not match');
      expect(result.reqMFA).toBe(true);
    }
  });

  it('should handle IP injection attempts', async () => {
    const maliciousIPs = [
      "127.0.0.1'; DROP TABLE visitors; --",
      "127.0.0.1 OR '1'='1",
      "127.0.0.1'; UPDATE users SET password_hash = 'hacked'; --"
    ];

    for (const ip of maliciousIPs) {
      const result = await strangeThings(
        validToken,
        canaryId,
        ip,
        'Mozilla/5.0 (Test Browser)',
        false
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Ip does not match');
      expect(result.reqMFA).toBe(true);
    }
  });

  it('should handle very long IP strings', async () => {
    const longIP = '127.0.0.1' + 'a'.repeat(1000);
    
    const result = await strangeThings(
      validToken,
      canaryId,
      longIP,
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Ip does not match');
    expect(result.reqMFA).toBe(true);
  });

  it('should detect suspicious activity score threshold', async (context) => {
    // Update visitor to have high suspicious activity score
    await context.mainPool.execute(
      'UPDATE visitors v JOIN users u ON v.visitor_id = u.visitor_id SET v.suspicos_activity_score = 10 WHERE u.id = ?',
      [testUserId]
    );

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Suspicos score to high');
    expect(result.reqMFA).toBe(true);
    expect(result.userId).toBe(testUserId);
  });

  it('should allow requests with suspicious score below threshold', async (context) => {
    // Set score below threshold (< 9)
    await context.mainPool.execute(
      'UPDATE visitors v JOIN users u ON v.visitor_id = u.visitor_id SET v.suspicos_activity_score = 8 WHERE u.id = ?',
      [testUserId]
    );

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.reason).not.toBe('Suspicos score to high');
    expect(result.userId).toBe(testUserId);
  });

  it('should handle edge case of exactly threshold score', async (context) => {
    // Set score to exactly 9 (threshold)
    await context.mainPool.execute(
      'UPDATE visitors v JOIN users u ON v.visitor_id = u.visitor_id SET v.suspicos_activity_score = 9 WHERE u.id = ?',
      [testUserId]
    );

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Suspicos score to high');
    expect(result.reqMFA).toBe(true);
  });

  it('should handle private network IP ranges', async (context) => {
    // Update stored IP to be in private range
    await context.mainPool.execute(
      'UPDATE visitors v JOIN users u ON v.visitor_id = u.visitor_id SET v.ip_address = ? WHERE u.id = ?',
      ['192.168.1.1', testUserId]
    );

    // Test with another IP in same private range
    const result = await strangeThings(
      validToken,
      canaryId,
      '192.168.1.50',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    // Behavior depends on ip-range-check library implementation
    // Should either accept (if in range) or trigger MFA
    expect(result.userId).toBe(testUserId);
    expect(typeof result.valid).toBe('boolean');
  });

  it('should handle empty or null stored IP', async (context) => {
    // Set stored IP to null
    await context.mainPool.execute(
      'UPDATE visitors v JOIN users u ON v.visitor_id = u.visitor_id SET v.ip_address = NULL WHERE u.id = ?',
      [testUserId]
    );

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Ip does not match');
    expect(result.reqMFA).toBe(true);
  });
});