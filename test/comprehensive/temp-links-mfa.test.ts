import { describe, test, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import mysql from 'mysql2/promise';
import mysql2 from 'mysql2';
import crypto from 'crypto';
import { configuration } from '../../src/jwtAuth/config/configuration.js';
import { tempJwtLink, verifyTempJwtLink } from '../../src/tempLinks.js';
import { sendTempMfaLink } from '../../src/jwtAuth/utils/emailMFA.js';

// Mock email functionality
vi.mock('../../src/jwtAuth/utils/email.js', () => ({
  mfaEmail: vi.fn().mockResolvedValue(undefined)
}));

describe('Temporary Links and MFA - Comprehensive Testing', () => {
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
    await promisePool.execute('DELETE FROM mfa_codes WHERE user_id BETWEEN 3000 AND 3999');
    await promisePool.execute('DELETE FROM refresh_tokens WHERE user_id BETWEEN 3000 AND 3999');
    await promisePool.execute('DELETE FROM users WHERE id BETWEEN 3000 AND 3999');
    await promisePool.execute('DELETE FROM banned WHERE canary_id LIKE "temp_test_%"');
    await promisePool.execute('DELETE FROM visitors WHERE canary_id LIKE "temp_test_%"');
  });

  afterAll(async () => {
    // Clean up test data
    await promisePool.execute('DELETE FROM mfa_codes WHERE user_id BETWEEN 3000 AND 3999');
    await promisePool.execute('DELETE FROM refresh_tokens WHERE user_id BETWEEN 3000 AND 3999');
    await promisePool.execute('DELETE FROM users WHERE id BETWEEN 3000 AND 3999');
    await promisePool.execute('DELETE FROM banned WHERE canary_id LIKE "temp_test_%"');
    await promisePool.execute('DELETE FROM visitors WHERE canary_id LIKE "temp_test_%"');
    
    if (promisePool) await promisePool.end();
    if (callbackPool) callbackPool.end();
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  // Helper function to setup test user and data
  async function setupTestUser(userId: number, visitorId: number) {
    const canaryId = `temp_test_${userId}_${crypto.randomUUID()}`;
    
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
    `, [userId, 'Test', 'User', `temptest${userId}@example.com`, 'hashed_password', visitorId]);

    return { userId, visitorId, canaryId };
  }

  // Helper function to create a refresh token for MFA testing
  async function createRefreshToken(userId: number) {
    const token = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await promisePool.execute(`
      INSERT INTO refresh_tokens 
      (user_id, token, valid, expiresAt, usage_count, created_at, session_started_at)
      VALUES (?, ?, ?, ?, ?, NOW(), NOW())
      ON DUPLICATE KEY UPDATE 
      valid = VALUES(valid),
      expiresAt = VALUES(expiresAt)
    `, [userId, hashedToken, true, expiresAt, 1]);

    return { raw: token, hashed: hashedToken };
  }

  describe('Temporary JWT Link Generation', () => {
    test('should generate valid temporary JWT link', () => {
      const payload = {
        visitor: 1001,
        subject: 'MAGIC_LINK_MFA_CHECKS',
        purpose: 'MFA',
        jti: crypto.randomUUID()
      };

      const token = tempJwtLink(payload);

      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3); // JWT has 3 parts
    });

    test('should generate unique tokens for same payload', () => {
      const payload = {
        visitor: 1002,
        subject: 'MAGIC_LINK_MFA_CHECKS',
        purpose: 'MFA',
        jti: crypto.randomUUID()
      };

      const token1 = tempJwtLink(payload);
      const token2 = tempJwtLink(payload);

      expect(token1).not.toBe(token2); // Should be different due to timestamp
    });

    test('should handle different payload types', () => {
      const payloadTypes = [
        {
          visitor: 1003,
          subject: 'MAGIC_LINK_MFA_CHECKS',
          purpose: 'MFA',
          jti: crypto.randomUUID()
        },
        {
          visitor: 1004,
          subject: 'MAGIC_LINK_PASSWORD_RESET',
          purpose: 'PASSWORD_RESET',
          jti: crypto.randomUUID()
        },
        {
          visitor: 1005,
          subject: 'MAGIC_LINK_EMAIL_VERIFICATION',
          purpose: 'EMAIL_VERIFICATION',
          jti: crypto.randomUUID()
        }
      ];

      payloadTypes.forEach(payload => {
        const token = tempJwtLink(payload);
        expect(token).toBeDefined();
        expect(typeof token).toBe('string');
      });
    });

    test('should handle boundary values for visitor ID', () => {
      const boundaryValues = [0, 1, -1, Number.MAX_SAFE_INTEGER];

      boundaryValues.forEach(visitorId => {
        const payload = {
          visitor: visitorId,
          subject: 'MAGIC_LINK_MFA_CHECKS',
          purpose: 'MFA',
          jti: crypto.randomUUID()
        };

        const token = tempJwtLink(payload);
        expect(token).toBeDefined();
      });
    });

    test('should handle malformed JTI values', () => {
      const malformedJtis = [
        '', // Empty string
        'a'.repeat(1000), // Very long
        'jti-with-special-chars!@#$%',
        'jti\x00with\x01null\x02bytes',
        null as any,
        undefined as any
      ];

      malformedJtis.forEach(jti => {
        const payload = {
          visitor: 1006,
          subject: 'MAGIC_LINK_MFA_CHECKS',
          purpose: 'MFA',
          jti: jti
        };

        if (jti !== null && jti !== undefined) {
          const token = tempJwtLink(payload);
          expect(token).toBeDefined();
        }
      });
    });
  });

  describe('Temporary JWT Link Verification', () => {
    test('should verify valid temporary link', () => {
      const payload = {
        visitor: 2001,
        subject: 'MAGIC_LINK_MFA_CHECKS',
        purpose: 'MFA',
        jti: crypto.randomUUID()
      };

      const token = tempJwtLink(payload);
      const result = verifyTempJwtLink(token);

      expect(result.valid).toBe(true);
      expect(result.payload).toMatchObject(payload);
    });

    test('should reject expired tokens', () => {
      // Create a token that expires immediately
      const payload = {
        visitor: 2002,
        subject: 'MAGIC_LINK_MFA_CHECKS',
        purpose: 'MFA',
        jti: crypto.randomUUID()
      };

      // Mock Date.now to make token appear expired
      const originalNow = Date.now;
      Date.now = vi.fn().mockReturnValue(0); // Very old timestamp

      const token = tempJwtLink(payload);

      // Restore Date.now
      Date.now = originalNow;

      const result = verifyTempJwtLink(token);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('expired');
    });

    test('should reject malformed tokens', () => {
      const malformedTokens = [
        '', // Empty string
        'not.a.jwt', // Not enough parts
        'invalid.jwt.token', // Invalid structure
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature', // Invalid signature
        'header.payload', // Missing signature
        'a'.repeat(1000), // Too long
        null as any,
        undefined as any,
        123 as any
      ];

      malformedTokens.forEach(token => {
        const result = verifyTempJwtLink(token);
        expect(result.valid).toBe(false);
        expect(result.reason).toBeDefined();
      });
    });

    test('should reject tokens with wrong signature', () => {
      const payload = {
        visitor: 2003,
        subject: 'MAGIC_LINK_MFA_CHECKS',
        purpose: 'MFA',
        jti: crypto.randomUUID()
      };

      const token = tempJwtLink(payload);
      
      // Tamper with the token
      const parts = token.split('.');
      parts[2] = 'tampered_signature';
      const tamperedToken = parts.join('.');

      const result = verifyTempJwtLink(tamperedToken);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('signature');
    });

    test('should handle tokens with modified payload', () => {
      const originalPayload = {
        visitor: 2004,
        subject: 'MAGIC_LINK_MFA_CHECKS',
        purpose: 'MFA',
        jti: crypto.randomUUID()
      };

      const token = tempJwtLink(originalPayload);
      
      // Attempt to modify the payload (this should fail signature verification)
      const parts = token.split('.');
      const modifiedPayload = Buffer.from(JSON.stringify({
        ...originalPayload,
        visitor: 9999 // Changed visitor ID
      })).toString('base64url');
      
      parts[1] = modifiedPayload;
      const modifiedToken = parts.join('.');

      const result = verifyTempJwtLink(modifiedToken);
      expect(result.valid).toBe(false);
    });
  });

  describe('MFA Link Generation and Management', () => {
    test('should successfully send MFA link', async () => {
      const { userId, visitorId } = await setupTestUser(3001, 3001);
      const refreshToken = await createRefreshToken(userId);

      const result = await sendTempMfaLink(
        { userId, visitor: visitorId },
        refreshToken.raw
      );

      expect(result).toBe(true);

      // Verify MFA code was stored in database
      const [rows] = await promisePool.execute<any[]>(
        'SELECT * FROM mfa_codes WHERE user_id = ?',
        [userId]
      );
      expect(rows.length).toBe(1);
      expect(rows[0].user_id).toBe(userId);
      expect(rows[0].used).toBe(0);
    });

    test('should handle duplicate MFA requests', async () => {
      const { userId, visitorId } = await setupTestUser(3002, 3002);
      const refreshToken = await createRefreshToken(userId);

      // Send first MFA link
      const result1 = await sendTempMfaLink(
        { userId, visitor: visitorId },
        refreshToken.raw
      );
      expect(result1).toBe(true);

      // Send second MFA link (should replace the first)
      const result2 = await sendTempMfaLink(
        { userId, visitor: visitorId },
        refreshToken.raw
      );
      expect(result2).toBe(true);

      // Should still have only one MFA code
      const [rows] = await promisePool.execute<any[]>(
        'SELECT * FROM mfa_codes WHERE user_id = ?',
        [userId]
      );
      expect(rows.length).toBe(1);
    });

    test('should generate valid MFA codes', async () => {
      const { userId, visitorId } = await setupTestUser(3003, 3003);
      const refreshToken = await createRefreshToken(userId);

      await sendTempMfaLink(
        { userId, visitor: visitorId },
        refreshToken.raw
      );

      // Check the generated code format
      const [rows] = await promisePool.execute<any[]>(
        'SELECT code_hash FROM mfa_codes WHERE user_id = ?',
        [userId]
      );

      expect(rows.length).toBe(1);
      expect(rows[0].code_hash).toHaveLength(64); // SHA256 hash
    });

    test('should set appropriate expiration times', async () => {
      const { userId, visitorId } = await setupTestUser(3004, 3004);
      const refreshToken = await createRefreshToken(userId);

      const beforeTime = new Date();
      await sendTempMfaLink(
        { userId, visitor: visitorId },
        refreshToken.raw
      );
      const afterTime = new Date();

      const [rows] = await promisePool.execute<any[]>(
        'SELECT expires_at FROM mfa_codes WHERE user_id = ?',
        [userId]
      );

      expect(rows.length).toBe(1);
      const expiresAt = new Date(rows[0].expires_at);
      
      // Should expire in about 7 minutes (420 seconds)
      const expectedExpiry = new Date(beforeTime.getTime() + 7 * 60 * 1000);
      const timeDiff = Math.abs(expiresAt.getTime() - expectedExpiry.getTime());
      expect(timeDiff).toBeLessThan(5000); // Within 5 seconds tolerance
    });

    test('should handle invalid refresh token', async () => {
      const { userId, visitorId } = await setupTestUser(3005, 3005);
      const invalidToken = crypto.randomBytes(32).toString('hex');

      const result = await sendTempMfaLink(
        { userId, visitor: visitorId },
        invalidToken
      );

      expect(result).toBe(false);
    });

    test('should handle non-existent user', async () => {
      const nonExistentUserId = 9999;
      const nonExistentVisitorId = 9999;
      const dummyToken = crypto.randomBytes(32).toString('hex');

      const result = await sendTempMfaLink(
        { userId: nonExistentUserId, visitor: nonExistentVisitorId },
        dummyToken
      );

      expect(result).toBe(false);
    });

    test('should handle database transaction failures gracefully', async () => {
      const { userId, visitorId } = await setupTestUser(3006, 3006);
      const refreshToken = await createRefreshToken(userId);

      // Force a constraint violation by creating invalid data
      try {
        await promisePool.execute(`
          INSERT INTO mfa_codes (user_id, token, jti, code_hash, expires_at)
          VALUES (?, 'invalid_foreign_key_token', ?, ?, NOW())
        `, [userId, crypto.randomUUID(), crypto.randomBytes(32).toString('hex')]);
      } catch (error) {
        // Expected to fail due to foreign key constraint
      }

      // Now try to send MFA link
      const result = await sendTempMfaLink(
        { userId, visitor: visitorId },
        refreshToken.raw
      );

      // Should handle gracefully
      expect(typeof result).toBe('boolean');
    });
  });

  describe('Edge Cases and Security', () => {
    test('should handle extremely large visitor IDs', async () => {
      const largeVisitorId = Number.MAX_SAFE_INTEGER;
      const payload = {
        visitor: largeVisitorId,
        subject: 'MAGIC_LINK_MFA_CHECKS',
        purpose: 'MFA',
        jti: crypto.randomUUID()
      };

      const token = tempJwtLink(payload);
      const result = verifyTempJwtLink(token);

      expect(result.valid).toBe(true);
      expect(result.payload.visitor).toBe(largeVisitorId);
    });

    test('should handle special characters in subjects and purposes', async () => {
      const specialCases = [
        {
          subject: 'MAGIC_LINK_MFA_CHECKS<script>alert(1)</script>',
          purpose: 'MFA'
        },
        {
          subject: 'MAGIC_LINK_MFA_CHECKS\x00\x01\x02',
          purpose: 'MFA\x00'
        },
        {
          subject: 'MAGIC_LINK_MFA_CHECKS' + 'A'.repeat(1000),
          purpose: 'MFA' + 'B'.repeat(500)
        }
      ];

      specialCases.forEach(testCase => {
        const payload = {
          visitor: 4001,
          subject: testCase.subject,
          purpose: testCase.purpose,
          jti: crypto.randomUUID()
        };

        const token = tempJwtLink(payload);
        const result = verifyTempJwtLink(token);

        expect(result.valid).toBe(true);
        expect(result.payload.subject).toBe(testCase.subject);
        expect(result.payload.purpose).toBe(testCase.purpose);
      });
    });

    test('should handle concurrent MFA link generation', async () => {
      const { userId, visitorId } = await setupTestUser(3007, 3007);
      const refreshToken = await createRefreshToken(userId);

      // Generate multiple MFA links concurrently
      const promises = Array.from({ length: 10 }, () =>
        sendTempMfaLink(
          { userId, visitor: visitorId },
          refreshToken.raw
        )
      );

      const results = await Promise.allSettled(promises);

      // Some should succeed, some might fail due to race conditions
      const fulfilled = results.filter(r => r.status === 'fulfilled');
      expect(fulfilled.length).toBeGreaterThan(0);

      // Should still have only one MFA code in the end
      const [rows] = await promisePool.execute<any[]>(
        'SELECT * FROM mfa_codes WHERE user_id = ?',
        [userId]
      );
      expect(rows.length).toBe(1);
    });

    test('should prevent JWT tampering attempts', async () => {
      const payload = {
        visitor: 4002,
        subject: 'MAGIC_LINK_MFA_CHECKS',
        purpose: 'MFA',
        jti: crypto.randomUUID()
      };

      const originalToken = tempJwtLink(payload);
      
      // Various tampering attempts
      const tamperingAttempts = [
        // Change algorithm to none
        originalToken.replace('HS256', 'none'),
        
        // Modify expiration time
        (() => {
          const parts = originalToken.split('.');
          const decodedPayload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
          decodedPayload.exp = Date.now() + 365 * 24 * 60 * 60 * 1000; // Extend expiry
          parts[1] = Buffer.from(JSON.stringify(decodedPayload)).toString('base64url');
          return parts.join('.');
        })(),
        
        // Swap parts around
        (() => {
          const parts = originalToken.split('.');
          return [parts[1], parts[0], parts[2]].join('.');
        })(),
        
        // Add extra parts
        originalToken + '.extra',
        
        // Remove parts
        originalToken.split('.').slice(0, 2).join('.')
      ];

      tamperingAttempts.forEach(tamperedToken => {
        const result = verifyTempJwtLink(tamperedToken);
        expect(result.valid).toBe(false);
      });
    });

    test('should handle token replay attacks', async () => {
      const payload = {
        visitor: 4003,
        subject: 'MAGIC_LINK_MFA_CHECKS',
        purpose: 'MFA',
        jti: crypto.randomUUID()
      };

      const token = tempJwtLink(payload);

      // Use the same token multiple times
      for (let i = 0; i < 5; i++) {
        const result = verifyTempJwtLink(token);
        expect(result.valid).toBe(true); // Should be valid each time (stateless JWT)
        expect(result.payload.jti).toBe(payload.jti); // Same JTI
      }

      // Note: Replay protection would typically be implemented at the application level
      // using JTI tracking in a database or cache
    });
  });

  describe('Performance and Stress Testing', () => {
    test('should handle rapid token generation', async () => {
      const startTime = Date.now();
      
      const tokens = Array.from({ length: 100 }, (_, i) => {
        const payload = {
          visitor: 5000 + i,
          subject: 'MAGIC_LINK_MFA_CHECKS',
          purpose: 'MFA',
          jti: crypto.randomUUID()
        };
        return tempJwtLink(payload);
      });

      const endTime = Date.now();
      
      expect(tokens.length).toBe(100);
      expect(endTime - startTime).toBeLessThan(1000); // Should complete quickly
      
      // All tokens should be unique
      expect(new Set(tokens).size).toBe(100);
    });

    test('should handle rapid token verification', async () => {
      const payload = {
        visitor: 5100,
        subject: 'MAGIC_LINK_MFA_CHECKS',
        purpose: 'MFA',
        jti: crypto.randomUUID()
      };

      const token = tempJwtLink(payload);
      
      const startTime = Date.now();
      
      const verifications = Array.from({ length: 100 }, () =>
        verifyTempJwtLink(token)
      );

      const endTime = Date.now();
      
      expect(verifications.length).toBe(100);
      expect(endTime - startTime).toBeLessThan(1000); // Should complete quickly
      
      // All verifications should be valid
      verifications.forEach(result => {
        expect(result.valid).toBe(true);
      });
    });

    test('should handle mixed operations under load', async () => {
      const operations = [];
      
      // Generate tokens
      for (let i = 0; i < 50; i++) {
        const payload = {
          visitor: 5200 + i,
          subject: 'MAGIC_LINK_MFA_CHECKS',
          purpose: 'MFA',
          jti: crypto.randomUUID()
        };
        operations.push(() => tempJwtLink(payload));
      }
      
      // Verify tokens
      const testToken = tempJwtLink({
        visitor: 5250,
        subject: 'MAGIC_LINK_MFA_CHECKS',
        purpose: 'MFA',
        jti: crypto.randomUUID()
      });
      
      for (let i = 0; i < 50; i++) {
        operations.push(() => verifyTempJwtLink(testToken));
      }
      
      const startTime = Date.now();
      const results = operations.map(op => op());
      const endTime = Date.now();
      
      expect(results.length).toBe(100);
      expect(endTime - startTime).toBeLessThan(2000); // Should complete in reasonable time
    });
  });
});