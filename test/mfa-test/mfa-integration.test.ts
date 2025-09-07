import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { strangeThings } from '../../src/anomalies.js';
import { generateRefreshToken } from '../../src/refreshTokens.js';
import { sendTempMfaLink } from '../../src/jwtAuth/utils/emailMFA.js';
import { tempJwtLink, verifyTempJwtLink } from '../../src/tempLinks.js';
import { createHash } from 'crypto';

describe('MFA Flow Integration Tests', () => {
  let testUserId: number;
  let testVisitorId: number;
  let validToken: string;
  let canaryId: string;

  beforeEach(async (context) => {
    testUserId = context.testUserId;
    
    // Get visitor info
    const [visitorRows] = await context.mainPool.execute<any[]>(
      'SELECT v.canary_id, v.visitor_id FROM visitors v JOIN users u ON v.visitor_id = u.visitor_id WHERE u.id = ?',
      [testUserId]
    );
    canaryId = visitorRows[0].canary_id;
    testVisitorId = visitorRows[0].visitor_id;

    // Generate valid token
    const tokenResult = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId);
    validToken = tokenResult.raw;

    // Create mfa_codes table if it doesn't exist
    await context.mainPool.execute(`
      CREATE TABLE IF NOT EXISTS mfa_codes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        token VARCHAR(64) NOT NULL,
        jti VARCHAR(191) NOT NULL,
        code_hash VARCHAR(64) NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_user_token (user_id, token),
        INDEX idx_expires (expires_at)
      )
    `);
  });

  afterEach(async (context) => {
    // Clean up test data
    await context.mainPool.execute('DELETE FROM refresh_tokens WHERE user_id = ?', [testUserId]);
    await context.mainPool.execute('DELETE FROM mfa_codes WHERE user_id = ?', [testUserId]);
  });

  describe('MFA Triggering from Anomalies', () => {
    it('should trigger MFA for IP address mismatch', async () => {
      const result = await strangeThings(
        validToken,
        canaryId,
        '192.168.1.100', // Different IP
        'Mozilla/5.0 (Test Browser)',
        false
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Ip does not match');
      expect(result.reqMFA).toBe(true);
      expect(result.userId).toBe(testUserId);
      expect(result.visitorId).toBe(testVisitorId);
    });

    it('should trigger MFA for canary cookie mismatch', async () => {
      const result = await strangeThings(
        validToken,
        'wrong-canary-id',
        '127.0.0.1',
        'Mozilla/5.0 (Test Browser)',
        false
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('new device');
      expect(result.reqMFA).toBe(true);
      expect(result.userId).toBe(testUserId);
      expect(result.visitorId).toBe(testVisitorId);
    });

    it('should trigger MFA for idle sessions', async (context) => {
      // Set old last_seen date
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
      expect(result.visitorId).toBe(testVisitorId);
    });

    it('should trigger MFA for high suspicious activity score', async (context) => {
      // Set high suspicious score
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
      expect(result.visitorId).toBe(testVisitorId);
    });

    it('should trigger MFA for session count exceeding limit', async (context) => {
      // Create 6 sessions (exceeds limit of 5)
      for (let i = 0; i < 6; i++) {
        await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId);
      }

      const newToken = (await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId)).raw;

      const result = await strangeThings(
        newToken,
        canaryId,
        '127.0.0.1',
        'Mozilla/5.0 (Test Browser)',
        false
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('more than 5 active sessions');
      expect(result.reqMFA).toBe(true);
      expect(result.userId).toBe(testUserId);
      expect(result.visitorId).toBe(testVisitorId);
    });
  });

  describe('MFA Link Generation and Validation', () => {
    // Mock the email system to avoid sending actual emails
    beforeEach(() => {
      vi.mock('../../src/jwtAuth/utils/systemEmailMap.js', () => ({
        mfaEmail: vi.fn().mockResolvedValue(true)
      }));
    });

    it('should generate MFA link successfully', async (context) => {
      // Add name field to user for email functionality
      await context.mainPool.execute(
        'UPDATE users SET name = ? WHERE id = ?',
        ['Test User', testUserId]
      );

      const result = await sendTempMfaLink(
        { userId: testUserId, visitor: testVisitorId },
        validToken
      );

      expect(result).toBe(true);

      // Verify MFA code was stored in database
      const hashedToken = createHash('sha256').update(validToken).digest('hex');
      const [mfaCodes] = await context.mainPool.execute<any[]>(
        'SELECT * FROM mfa_codes WHERE user_id = ? AND token = ? AND expires_at > NOW()',
        [testUserId, hashedToken]
      );

      expect(mfaCodes.length).toBe(1);
      expect(mfaCodes[0].user_id).toBe(testUserId);
      expect(mfaCodes[0].token).toBe(hashedToken);
      expect(mfaCodes[0].jti).toBeDefined();
      expect(mfaCodes[0].code_hash).toBeDefined();
    });

    it('should reuse existing valid MFA code', async (context) => {
      // Add name field to user
      await context.mainPool.execute(
        'UPDATE users SET name = ? WHERE id = ?',
        ['Test User', testUserId]
      );

      // Generate first MFA link
      const result1 = await sendTempMfaLink(
        { userId: testUserId, visitor: testVisitorId },
        validToken
      );
      expect(result1).toBe(true);

      // Generate second MFA link with same token - should reuse existing
      const result2 = await sendTempMfaLink(
        { userId: testUserId, visitor: testVisitorId },
        validToken
      );
      expect(result2).toBe(true);

      // Should still have only one MFA code
      const hashedToken = createHash('sha256').update(validToken).digest('hex');
      const [mfaCodes] = await context.mainPool.execute<any[]>(
        'SELECT * FROM mfa_codes WHERE user_id = ? AND token = ?',
        [testUserId, hashedToken]
      );

      expect(mfaCodes.length).toBe(1);
    });

    it('should clean up old MFA codes when generating new ones', async (context) => {
      // Add name field to user
      await context.mainPool.execute(
        'UPDATE users SET name = ? WHERE id = ?',
        ['Test User', testUserId]
      );

      // Insert old expired MFA code
      const oldExpiry = new Date(Date.now() - 60 * 1000); // 1 minute ago
      await context.mainPool.execute(
        'INSERT INTO mfa_codes (user_id, token, jti, code_hash, expires_at) VALUES (?, ?, ?, ?, ?)',
        [testUserId, 'old-token', 'old-jti', 'old-hash', oldExpiry]
      );

      // Generate new MFA link
      await sendTempMfaLink(
        { userId: testUserId, visitor: testVisitorId },
        validToken
      );

      // Old codes should be cleaned up
      const [allCodes] = await context.mainPool.execute<any[]>(
        'SELECT * FROM mfa_codes WHERE user_id = ?',
        [testUserId]
      );

      expect(allCodes.length).toBe(1);
      expect(allCodes[0].jti).not.toBe('old-jti');
    });
  });

  describe('Temp Link Token Validation', () => {
    it('should generate and validate temp JWT link', () => {
      const payload = {
        visitor: testVisitorId,
        subject: 'MAGIC_LINK_MFA_CHECKS',
        purpose: 'MFA' as const,
        jti: `test-jti-${Date.now()}`
      };

      // Generate temp link
      const token = tempJwtLink(payload);
      expect(typeof token).toBe('string');
      expect(token.length).toBeGreaterThan(0);

      // Verify temp link
      const verification = verifyTempJwtLink(token);
      expect(verification.valid).toBe(true);
      expect(verification.payload).toBeDefined();
      expect(verification.payload?.visitor).toBe(testVisitorId);
      expect(verification.payload?.purpose).toBe('MFA');
    });

    it('should reject invalid temp JWT links', () => {
      const invalidToken = 'invalid.jwt.token';
      
      const verification = verifyTempJwtLink(invalidToken);
      expect(verification.valid).toBe(false);
      expect(verification.errorType).toBeDefined();
    });

    it('should reject temp JWT links not in cache', async () => {
      // Create a valid-looking JWT that's not in the cache
      const payload = {
        visitor: testVisitorId,
        subject: 'MAGIC_LINK_MFA_CHECKS',
        purpose: 'MFA' as const,
        jti: `uncached-jti-${Date.now()}`
      };

      const token = tempJwtLink(payload);
      
      // Clear the cache entry (simulating expired/missing cache)
      const magicLinksModule = await import('../../src/jwtAuth/utils/magicLinksCache.js');
      magicLinksModule.magicLinksCache().delete(token);

      const verification = verifyTempJwtLink(token);
      expect(verification.valid).toBe(false);
      expect(verification.errorType).toBe('InvalidPayloadType');
    });

    it('should validate visitor ID match in temp JWT', async () => {
      const payload = {
        visitor: testVisitorId,
        subject: 'MAGIC_LINK_MFA_CHECKS',
        purpose: 'MFA' as const,
        jti: `visitor-test-${Date.now()}`
      };

      const token = tempJwtLink(payload);
      
      // Manually modify cache to have different visitor ID
      const magicLinksModule = await import('../../src/jwtAuth/utils/magicLinksCache.js');
      const cache = magicLinksModule.magicLinksCache().get(token);
      if (cache) {
        cache.visitor = 999999; // Different visitor ID
        magicLinksModule.magicLinksCache().set(token, cache);
      }

      const verification = verifyTempJwtLink(token);
      expect(verification.valid).toBe(false);
      expect(verification.errorType).toBe('Invalid visitor id');
    });
  });

  describe('MFA Bypass Conditions', () => {
    it('should bypass session limits after recent MFA', async (context) => {
      // Set recent MFA timestamp
      const now = new Date();
      await context.mainPool.execute(
        'UPDATE users SET last_mfa_at = ? WHERE id = ?',
        [now, testUserId]
      );

      // Create more sessions than normally allowed
      for (let i = 0; i < 6; i++) {
        await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId);
      }

      const newToken = (await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId)).raw;

      const result = await strangeThings(
        newToken,
        canaryId,
        '127.0.0.1',
        'Mozilla/5.0 (Test Browser)',
        false
      );

      // Should bypass session limit due to recent MFA
      expect(result.reason).not.toBe('more than 5 active sessions');
    });

    it('should not bypass session limits with old MFA', async (context) => {
      // Set old MFA timestamp (beyond bypass period)
      const oldMfa = new Date(Date.now() - 25 * 60 * 60 * 1000); // 25 hours ago
      await context.mainPool.execute(
        'UPDATE users SET last_mfa_at = ? WHERE id = ?',
        [oldMfa, testUserId]
      );

      // Create more sessions than allowed
      for (let i = 0; i < 6; i++) {
        await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId);
      }

      const newToken = (await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId)).raw;

      const result = await strangeThings(
        newToken,
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

    it('should update last_mfa_at after successful MFA verification', async (context) => {
      // Get initial MFA timestamp
      const [beforeRows] = await context.mainPool.execute<any[]>(
        'SELECT last_mfa_at FROM users WHERE id = ?',
        [testUserId]
      );
      const beforeMfa = beforeRows[0].last_mfa_at;

      // Simulate successful MFA completion
      const now = new Date();
      await context.mainPool.execute(
        'UPDATE users SET last_mfa_at = ? WHERE id = ?',
        [now, testUserId]
      );

      // Verify timestamp was updated
      const [afterRows] = await context.mainPool.execute<any[]>(
        'SELECT last_mfa_at FROM users WHERE id = ?',
        [testUserId]
      );
      const afterMfa = afterRows[0].last_mfa_at;

      expect(new Date(afterMfa).getTime()).toBeGreaterThan(
        beforeMfa ? new Date(beforeMfa).getTime() : 0
      );
    });
  });

  describe('MFA Security Edge Cases', () => {
    it('should handle concurrent MFA requests', async (context) => {
      // Add name field to user
      await context.mainPool.execute(
        'UPDATE users SET name = ? WHERE id = ?',
        ['Test User', testUserId]
      );

      // Generate multiple MFA links concurrently
      const promises = Array(3).fill(0).map(() =>
        sendTempMfaLink(
          { userId: testUserId, visitor: testVisitorId },
          validToken
        )
      );

      const results = await Promise.all(promises);
      
      // All should succeed (reusing the same valid code)
      results.forEach(result => {
        expect(result).toBe(true);
      });

      // Should still have only one active MFA code
      const hashedToken = createHash('sha256').update(validToken).digest('hex');
      const [mfaCodes] = await context.mainPool.execute<any[]>(
        'SELECT * FROM mfa_codes WHERE user_id = ? AND token = ? AND expires_at > NOW()',
        [testUserId, hashedToken]
      );

      expect(mfaCodes.length).toBe(1);
    });

    it('should handle MFA code expiry properly', async (context) => {
      // Manually insert expired MFA code
      const hashedToken = createHash('sha256').update(validToken).digest('hex');
      const expiredTime = new Date(Date.now() - 60 * 1000); // 1 minute ago
      
      await context.mainPool.execute(
        'INSERT INTO mfa_codes (user_id, token, jti, code_hash, expires_at) VALUES (?, ?, ?, ?, ?)',
        [testUserId, hashedToken, 'expired-jti', 'expired-hash', expiredTime]
      );

      // Add name field to user
      await context.mainPool.execute(
        'UPDATE users SET name = ? WHERE id = ?',
        ['Test User', testUserId]
      );

      // Try to generate new MFA link - should clean up expired and create new
      const result = await sendTempMfaLink(
        { userId: testUserId, visitor: testVisitorId },
        validToken
      );

      expect(result).toBe(true);

      // Should have new valid MFA code
      const [validCodes] = await context.mainPool.execute<any[]>(
        'SELECT * FROM mfa_codes WHERE user_id = ? AND token = ? AND expires_at > NOW()',
        [testUserId, hashedToken]
      );

      expect(validCodes.length).toBe(1);
      expect(validCodes[0].jti).not.toBe('expired-jti');
    });

    it('should generate unique JTI for each MFA request', async (context) => {
      // Add name field to user
      await context.mainPool.execute(
        'UPDATE users SET name = ? WHERE id = ?',
        ['Test User', testUserId]
      );

      const user = { userId: testUserId, visitor: testVisitorId };
      
      // Generate first MFA link
      await sendTempMfaLink(user, validToken);
      
      // Get the JTI
      const hashedToken = createHash('sha256').update(validToken).digest('hex');
      const [firstCode] = await context.mainPool.execute<any[]>(
        'SELECT jti FROM mfa_codes WHERE user_id = ? AND token = ?',
        [testUserId, hashedToken]
      );
      
      // Clean up and generate new MFA link with different token
      await context.mainPool.execute('DELETE FROM mfa_codes WHERE user_id = ?', [testUserId]);
      
      const newToken = (await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId)).raw;
      await sendTempMfaLink(user, newToken);
      
      const newHashedToken = createHash('sha256').update(newToken).digest('hex');
      const [secondCode] = await context.mainPool.execute<any[]>(
        'SELECT jti FROM mfa_codes WHERE user_id = ? AND token = ?',
        [testUserId, newHashedToken]
      );

      // JTIs should be different
      expect(firstCode[0].jti).not.toBe(secondCode[0].jti);
    });
  });
});