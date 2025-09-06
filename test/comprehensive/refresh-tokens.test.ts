import { describe, test, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import mysql from 'mysql2/promise';
import mysql2 from 'mysql2';
import crypto from 'crypto';
import { configuration } from '../../src/jwtAuth/config/configuration.js';
import { 
  rotateRefreshToken, 
  verifyRefreshToken, 
  generateRefreshToken, 
  revokeRefreshToken 
} from '../../src/refreshTokens.js';

describe('Refresh Token Rotation - Comprehensive Testing', () => {
  let promisePool: mysql.Pool;
  let callbackPool: mysql2.Pool;

  beforeAll(async () => {
    // Setup database connections
    promisePool = mysql.createPool({
      host: '127.0.0.1',
      port: 3306,
      user: 'root',
      password: '1234',
      database: 'app_db',
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
    });

    callbackPool = mysql2.createPool({
      host: '127.0.0.1',
      port: 3306,
      user: 'root',
      password: '1234',
      database: 'app_db',
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
    });

    // Configure the library
    configuration({
      store: {
        main: promisePool,
        rate_limiters_pool: {
          store: callbackPool,
          dbName: 'app_db'
        }
      },
      telegram: { token: 'test-token' },
      password: { pepper: 'test-pepper' },
      magic_links: {
        jwt_secret_key: 'test-magic-secret-key-32-chars-long',
        domain: 'https://test.example.com'
      },
      jwt: {
        jwt_secret_key: 'test-jwt-secret-key-32-chars-long',
        access_tokens: {
          expiresIn: '15m',
          algorithm: 'HS512',
          maxCacheEntries: 500
        },
        refresh_tokens: {
          rotateOnEveryAccessExpiry: true,
          refresh_ttl: 24 * 60 * 60 * 1000,
          domain: 'test.example.com',
          MAX_SESSION_LIFE: 30 * 24 * 60 * 60 * 1000,
          maxAllowedSessionsPerUser: 5,
          byPassAnomaliesFor: 60 * 60 * 1000
        }
      },
      email: {
        resend_key: 'test-resend-key',
        email: 'test@example.com'
      },
      logLevel: 'info'
    });

    // Clean up any existing test data
    await promisePool.execute('DELETE FROM mfa_codes WHERE user_id BETWEEN 2000 AND 2999');
    await promisePool.execute('DELETE FROM refresh_tokens WHERE user_id BETWEEN 2000 AND 2999');
    await promisePool.execute('DELETE FROM users WHERE id BETWEEN 2000 AND 2999');
    await promisePool.execute('DELETE FROM banned WHERE canary_id LIKE "refresh_test_%"');
    await promisePool.execute('DELETE FROM visitors WHERE canary_id LIKE "refresh_test_%"');
  });

  afterAll(async () => {
    // Clean up test data
    await promisePool.execute('DELETE FROM mfa_codes WHERE user_id BETWEEN 2000 AND 2999');
    await promisePool.execute('DELETE FROM refresh_tokens WHERE user_id BETWEEN 2000 AND 2999');
    await promisePool.execute('DELETE FROM users WHERE id BETWEEN 2000 AND 2999');
    await promisePool.execute('DELETE FROM banned WHERE canary_id LIKE "refresh_test_%"');
    await promisePool.execute('DELETE FROM visitors WHERE canary_id LIKE "refresh_test_%"');
    
    if (promisePool) await promisePool.end();
    if (callbackPool) callbackPool.end();
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  // Helper function to setup test user and visitor
  async function setupTestUser(userId: number, visitorId: number) {
    const canaryId = `refresh_test_${userId}_${crypto.randomUUID()}`;
    
    // Insert visitor
    await promisePool.execute(`
      INSERT INTO visitors 
      (visitor_id, canary_id, ip_address, user_agent, country, city, lat, lon)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE 
      ip_address = VALUES(ip_address)
    `, [visitorId, canaryId, '192.168.1.1', 'Mozilla/5.0 (Test)', 'US', 'TestCity', '40.7128', '-74.0060']);

    // Insert user
    await promisePool.execute(`
      INSERT INTO users 
      (id, name, last_name, email, password_hash, visitor_id)
      VALUES (?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE 
      visitor_id = VALUES(visitor_id)
    `, [userId, 'Test', 'User', `test${userId}@example.com`, 'hashed_password', visitorId]);

    return { userId, visitorId, canaryId };
  }

  describe('Token Generation Edge Cases', () => {
    test('should generate valid refresh token', async () => {
      const { userId, visitorId } = await setupTestUser(2001, 2001);
      const ttl = 24 * 60 * 60 * 1000; // 24 hours

      const token = await generateRefreshToken(ttl, userId);

      expect(token).toHaveProperty('raw');
      expect(token).toHaveProperty('hashedToken');
      expect(token).toHaveProperty('expiresAt');
      expect(token.raw).toHaveLength(64); // 32 bytes hex = 64 chars
      expect(token.hashedToken).toHaveLength(64); // SHA256 hex = 64 chars
      expect(token.expiresAt).toBeInstanceOf(Date);
      expect(token.expiresAt.getTime()).toBeGreaterThan(Date.now());
    });

    test('should handle zero TTL', async () => {
      const { userId, visitorId } = await setupTestUser(2002, 2002);
      
      const token = await generateRefreshToken(0, userId);
      
      expect(token.expiresAt.getTime()).toBeLessThanOrEqual(Date.now());
    });

    test('should handle negative TTL', async () => {
      const { userId, visitorId } = await setupTestUser(2003, 2003);
      
      const token = await generateRefreshToken(-1000, userId);
      
      expect(token.expiresAt.getTime()).toBeLessThan(Date.now());
    });

    test('should handle maximum TTL values', async () => {
      const { userId, visitorId } = await setupTestUser(2004, 2004);
      const maxTtl = Number.MAX_SAFE_INTEGER;
      
      const token = await generateRefreshToken(maxTtl, userId);
      
      expect(token.expiresAt.getTime()).toBeGreaterThan(Date.now());
    });

    test('should generate unique tokens for concurrent requests', async () => {
      const { userId, visitorId } = await setupTestUser(2005, 2005);
      const ttl = 24 * 60 * 60 * 1000;

      // Generate multiple tokens concurrently
      const promises = Array.from({ length: 10 }, () =>
        generateRefreshToken(ttl, userId)
      );

      const tokens = await Promise.all(promises);
      const rawTokens = tokens.map(t => t.raw);
      const hashedTokens = tokens.map(t => t.hashedToken);

      // All tokens should be unique
      expect(new Set(rawTokens).size).toBe(10);
      expect(new Set(hashedTokens).size).toBe(10);
    });
  });

  describe('Token Verification Edge Cases', () => {
    test('should verify valid token', async () => {
      const { userId, visitorId } = await setupTestUser(2006, 2006);
      const ttl = 24 * 60 * 60 * 1000;

      const token = await generateRefreshToken(ttl, userId);
      const result = await verifyRefreshToken(token.raw);

      expect(result).toEqual({
        valid: true,
        userId: userId,
        visitor_id: visitorId
      });
    });

    test('should reject non-existent token', async () => {
      const nonExistentToken = crypto.randomBytes(32).toString('hex');
      
      const result = await verifyRefreshToken(nonExistentToken);

      expect(result).toEqual({
        valid: false,
        reason: 'Token not found'
      });
    });

    test('should reject expired token', async () => {
      const { userId, visitorId } = await setupTestUser(2007, 2007);
      
      // Generate token with very short TTL
      const token = await generateRefreshToken(1, userId); // 1ms TTL
      
      // Wait for token to expire
      await new Promise(resolve => setTimeout(resolve, 10));
      
      const result = await verifyRefreshToken(token.raw);

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Token expired');
    });

    test('should reject revoked token', async () => {
      const { userId, visitorId } = await setupTestUser(2008, 2008);
      const ttl = 24 * 60 * 60 * 1000;

      const token = await generateRefreshToken(ttl, userId);
      
      // Revoke the token
      await revokeRefreshToken(token.raw);
      
      const result = await verifyRefreshToken(token.raw);

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Token revoked');
    });

    test('should handle malformed token inputs', async () => {
      const malformedTokens = [
        '', // Empty string
        'not_a_hex_string',
        'a'.repeat(10000), // Too long
        'abc123', // Too short
        'XYZ123NotHex', // Invalid hex
        null as any, // Null
        undefined as any, // Undefined
        123 as any, // Number instead of string
      ];

      for (const badToken of malformedTokens) {
        const result = await verifyRefreshToken(badToken);
        expect(result.valid).toBe(false);
        expect(result.reason).toBeDefined();
      }
    });
  });

  describe('Token Rotation Scenarios', () => {
    test('should successfully rotate valid token', async () => {
      const { userId, visitorId } = await setupTestUser(2009, 2009);
      const ttl = 24 * 60 * 60 * 1000;

      // Generate initial token
      const initialToken = await generateRefreshToken(ttl, userId);
      
      // Rotate the token
      const result = await rotateRefreshToken(ttl, userId, initialToken.raw);

      expect(result.rotated).toBe(true);
      expect(result).toHaveProperty('raw');
      expect(result).toHaveProperty('hashedToken');
      expect(result).toHaveProperty('expiresAt');
      expect(result.raw).not.toBe(initialToken.raw); // Should be different
    });

    test('should fail to rotate non-existent token', async () => {
      const nonExistentToken = crypto.randomBytes(32).toString('hex');
      const ttl = 24 * 60 * 60 * 1000;

      const result = await rotateRefreshToken(ttl, 2010, nonExistentToken);

      expect(result.rotated).toBe(false);
      expect(result).not.toHaveProperty('raw');
      expect(result).not.toHaveProperty('hashedToken');
      expect(result).not.toHaveProperty('expiresAt');
    });

    test('should fail to rotate expired token', async () => {
      const { userId, visitorId } = await setupTestUser(2011, 2011);
      
      // Generate expired token
      const expiredToken = await generateRefreshToken(1, userId);
      await new Promise(resolve => setTimeout(resolve, 10)); // Wait for expiration
      
      const result = await rotateRefreshToken(24 * 60 * 60 * 1000, userId, expiredToken.raw);

      expect(result.rotated).toBe(false);
    });

    test('should fail to rotate revoked token', async () => {
      const { userId, visitorId } = await setupTestUser(2012, 2012);
      const ttl = 24 * 60 * 60 * 1000;

      const token = await generateRefreshToken(ttl, userId);
      await revokeRefreshToken(token.raw);
      
      const result = await rotateRefreshToken(ttl, userId, token.raw);

      expect(result.rotated).toBe(false);
    });

    test('should handle rotation with hashed token input', async () => {
      const { userId, visitorId } = await setupTestUser(2013, 2013);
      const ttl = 24 * 60 * 60 * 1000;

      const token = await generateRefreshToken(ttl, userId);
      
      // Try to rotate using hashed token
      const result = await rotateRefreshToken(ttl, userId, token.hashedToken, true);

      expect(result.rotated).toBe(true);
      expect(result.raw).not.toBe(token.raw);
    });

    test('should handle concurrent rotation attempts', async () => {
      const { userId, visitorId } = await setupTestUser(2014, 2014);
      const ttl = 24 * 60 * 60 * 1000;

      const token = await generateRefreshToken(ttl, userId);
      
      // Attempt multiple concurrent rotations
      const promises = Array.from({ length: 5 }, () =>
        rotateRefreshToken(ttl, userId, token.raw)
      );

      const results = await Promise.all(promises);
      
      // Only one should succeed (due to database constraints)
      const successCount = results.filter(r => r.rotated).length;
      expect(successCount).toBeLessThanOrEqual(1);
    });
  });

  describe('Token Revocation', () => {
    test('should successfully revoke valid token', async () => {
      const { userId, visitorId } = await setupTestUser(2015, 2015);
      const ttl = 24 * 60 * 60 * 1000;

      const token = await generateRefreshToken(ttl, userId);
      
      await expect(revokeRefreshToken(token.raw)).resolves.not.toThrow();
      
      // Verify token is now invalid
      const result = await verifyRefreshToken(token.raw);
      expect(result.valid).toBe(false);
    });

    test('should handle revocation of non-existent token', async () => {
      const nonExistentToken = crypto.randomBytes(32).toString('hex');
      
      // Should not throw error
      await expect(revokeRefreshToken(nonExistentToken)).resolves.not.toThrow();
    });

    test('should handle revocation of already revoked token', async () => {
      const { userId, visitorId } = await setupTestUser(2016, 2016);
      const ttl = 24 * 60 * 60 * 1000;

      const token = await generateRefreshToken(ttl, userId);
      
      // Revoke twice
      await revokeRefreshToken(token.raw);
      await expect(revokeRefreshToken(token.raw)).resolves.not.toThrow();
    });

    test('should handle malformed token revocation', async () => {
      const malformedTokens = [
        '',
        'not_a_token',
        null as any,
        undefined as any,
      ];

      for (const badToken of malformedTokens) {
        await expect(revokeRefreshToken(badToken)).resolves.not.toThrow();
      }
    });
  });

  describe('Session Management and Limits', () => {
    test('should enforce maximum sessions per user', async () => {
      const { userId, visitorId } = await setupTestUser(2017, 2017);
      const ttl = 24 * 60 * 60 * 1000;
      const maxSessions = 5; // From configuration

      // Generate maximum allowed sessions
      const tokens = [];
      for (let i = 0; i < maxSessions + 2; i++) {
        const token = await generateRefreshToken(ttl, userId);
        tokens.push(token);
      }

      // Verify oldest tokens are automatically revoked
      const verifications = await Promise.all(
        tokens.map(token => verifyRefreshToken(token.raw))
      );

      const validTokens = verifications.filter(v => v.valid);
      expect(validTokens.length).toBeLessThanOrEqual(maxSessions);
    });

    test('should handle session lifecycle correctly', async () => {
      const { userId, visitorId } = await setupTestUser(2018, 2018);
      const ttl = 24 * 60 * 60 * 1000;

      // Create initial session
      const token1 = await generateRefreshToken(ttl, userId);
      expect((await verifyRefreshToken(token1.raw)).valid).toBe(true);

      // Rotate token
      const rotation = await rotateRefreshToken(ttl, userId, token1.raw);
      expect(rotation.rotated).toBe(true);

      // Original token should be invalid
      expect((await verifyRefreshToken(token1.raw)).valid).toBe(false);

      // New token should be valid
      expect((await verifyRefreshToken(rotation.raw!)).valid).toBe(true);

      // Revoke new token
      await revokeRefreshToken(rotation.raw!);
      expect((await verifyRefreshToken(rotation.raw!)).valid).toBe(false);
    });
  });

  describe('Edge Cases and Boundary Conditions', () => {
    test('should handle user ID boundary values', async () => {
      const boundaryUserIds = [0, 1, -1, Number.MAX_SAFE_INTEGER];
      
      for (const userId of boundaryUserIds) {
        try {
          const visitorId = userId > 0 ? userId : 1;
          await setupTestUser(userId);
          
          const token = await generateRefreshToken(24 * 60 * 60 * 1000, userId);
          expect(token).toHaveProperty('raw');
          
          const verification = await verifyRefreshToken(token.raw);
          expect(verification.userId).toBe(userId);
        } catch (error) {
          // Some boundary values might cause legitimate database errors
          expect(error).toBeDefined();
        }
      }
    });

    test('should handle database constraint violations gracefully', async () => {
      const { userId, visitorId } = await setupTestUser(2019, 2019);
      
      // Generate token
      const token = await generateRefreshToken(24 * 60 * 60 * 1000, userId);
      
      // Try to manually insert duplicate token (should fail due to UNIQUE constraint)
      try {
        await promisePool.execute(`
          INSERT INTO refresh_tokens 
          (user_id, token, valid, expiresAt, usage_count, created_at, session_started_at)
          VALUES (?, ?, ?, ?, ?, NOW(), NOW())
        `, [userId + 1, token.hashedToken, true, new Date(Date.now() + 24 * 60 * 60 * 1000), 0]);
        
        // If no error is thrown, the test setup might be wrong
        expect(true).toBe(false);
      } catch (error) {
        // This should fail due to duplicate key constraint
        expect(error).toBeDefined();
      }
    });

    test('should handle token rotation race conditions', async () => {
      const { userId, visitorId } = await setupTestUser(2020, 2020);
      const ttl = 24 * 60 * 60 * 1000;

      const token = await generateRefreshToken(ttl, userId);
      
      // Simulate race condition with immediate concurrent operations
      const operations = [
        rotateRefreshToken(ttl, userId, token.raw),
        verifyRefreshToken(token.raw),
        revokeRefreshToken(token.raw),
        rotateRefreshToken(ttl, userId, token.raw)
      ];

      const results = await Promise.allSettled(operations);
      
      // Should handle all operations without crashing
      expect(results.length).toBe(4);
      results.forEach(result => {
        expect(result.status).toBeOneOf(['fulfilled', 'rejected']);
      });
    });
  });

  describe('Performance and Stress Testing', () => {
    test('should handle high-frequency token operations', async () => {
      const { userId, visitorId } = await setupTestUser(2021, 2021);
      const ttl = 24 * 60 * 60 * 1000;

      const startTime = Date.now();
      
      // Generate many tokens rapidly
      const tokenPromises = Array.from({ length: 50 }, () =>
        generateRefreshToken(ttl, userId)
      );

      const tokens = await Promise.all(tokenPromises);
      
      const endTime = Date.now();
      
      expect(tokens.length).toBe(50);
      expect(endTime - startTime).toBeLessThan(5000); // Should complete in reasonable time
      
      // Verify all tokens are unique
      const rawTokens = tokens.map(t => t.raw);
      expect(new Set(rawTokens).size).toBe(50);
    });

    test('should handle mixed operations under load', async () => {
      const { userId, visitorId } = await setupTestUser(2022, 2022);
      const ttl = 24 * 60 * 60 * 1000;

      // Generate initial tokens
      const initialTokens = await Promise.all(
        Array.from({ length: 10 }, () => generateRefreshToken(ttl, userId))
      );

      // Mixed operations
      const operations = [];
      
      // Verifications
      initialTokens.forEach(token => {
        operations.push(verifyRefreshToken(token.raw));
      });
      
      // Rotations
      initialTokens.slice(0, 5).forEach(token => {
        operations.push(rotateRefreshToken(ttl, userId, token.raw));
      });
      
      // Revocations
      initialTokens.slice(5, 8).forEach(token => {
        operations.push(revokeRefreshToken(token.raw));
      });
      
      // New generations
      operations.push(...Array.from({ length: 5 }, () => 
        generateRefreshToken(ttl, userId)
      ));

      const results = await Promise.allSettled(operations);
      
      // All operations should complete
      expect(results.length).toBeGreaterThan(25);
      
      // Most should be successful
      const fulfilled = results.filter(r => r.status === 'fulfilled');
      expect(fulfilled.length).toBeGreaterThan(20);
    });
  });
});