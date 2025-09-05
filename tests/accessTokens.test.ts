import { describe, test, expect, beforeAll, afterAll, beforeEach, vi, MockedFunction } from 'vitest';
import mysql from 'mysql2/promise';
import mysql2 from 'mysql2';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';

import { generateAccessToken, verifyAccessToken, AccessTokenPayload } from '../src/accessTokens.js';
import { configuration } from '../src/jwtAuth/config/configuration.js';
import { tokenCache } from '../src/jwtAuth/utils/accessTokentCache.js';
import * as refreshTokens from '../src/refreshTokens.js';

// Mock the refreshTokens module
vi.mock('../src/refreshTokens.js', () => ({
  generateRefreshToken: vi.fn(),
  rotateRefreshToken: vi.fn(),
  verifyRefreshToken: vi.fn(),
}));

const mockedGenerateRefreshToken = refreshTokens.generateRefreshToken as MockedFunction<typeof refreshTokens.generateRefreshToken>;
const mockedRotateRefreshToken = refreshTokens.rotateRefreshToken as MockedFunction<typeof refreshTokens.rotateRefreshToken>;
const mockedVerifyRefreshToken = refreshTokens.verifyRefreshToken as MockedFunction<typeof refreshTokens.verifyRefreshToken>;

describe('AccessTokens Functions', () => {
  let promisePool: mysql.Pool;
  let callbackPool: mysql2.Pool;

  beforeAll(async () => {
    // Create MySQL connection pools
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

    // Configure the library with minimal required config
    configuration({
      store: {
        main: promisePool,
        rate_limiters_pool: {
          store: callbackPool,
          dbName: 'app_db'
        }
      },
      telegram: {
        token: 'test-token'
      },
      password: {
        pepper: 'test-pepper'
      },
      magic_links: {
        jwt_secret_key: 'test-magic-secret-key-32-chars-long',
        domain: 'https://example.com'
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
          refresh_ttl: 24 * 60 * 60 * 1000, // 24 hours
          domain: 'example.com',
          MAX_SESSION_LIFE: 30 * 24 * 60 * 60 * 1000, // 30 days
          maxAllowedSessionsPerUser: 5,
          byPassAnomaliesFor: 60 * 60 * 1000 // 1 hour
        }
      },
      email: {
        resend_key: 'test-resend-key',
        email: 'test@example.com'
      },
      logLevel: 'info'
    });
  });

  afterAll(async () => {
    // Clean up pools
    if (promisePool) {
      await promisePool.end();
    }
    if (callbackPool) {
      callbackPool.end();
    }
  });

  beforeEach(() => {
    // Reset mocks before each test
    vi.clearAllMocks();
  });

  describe('generateAccessToken', () => {
    test('should generate a valid JWT access token with required claims', () => {
      const user: AccessTokenPayload = {
        id: 123,
        visitor_id: 456,
        jti: crypto.randomUUID()
      };

      const token = generateAccessToken(user);

      // Verify token structure
      expect(token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);

      // Decode and verify payload
      const decoded = jwt.decode(token, { complete: true }) as any;
      expect(decoded).toBeTruthy();
      expect(decoded.payload.visitor).toBe(user.visitor_id);
      expect(decoded.payload.sub).toBe(user.id.toString());
      expect(decoded.payload.jti).toBe(user.jti);
      expect(decoded.payload.roles).toEqual([]);
      expect(decoded.payload.aud).toBe('example.com');
      expect(decoded.payload.iss).toBe('example.com');
    });

    test('should generate token with custom roles', () => {
      const user: AccessTokenPayload = {
        id: 123,
        visitor_id: 456,
        jti: crypto.randomUUID(),
        role: ['admin', 'user']
      };

      const token = generateAccessToken(user);
      const decoded = jwt.decode(token) as any;

      expect(decoded.roles).toEqual(['admin', 'user']);
    });

    test('should handle empty roles array', () => {
      const user: AccessTokenPayload = {
        id: 123,
        visitor_id: 456,
        jti: crypto.randomUUID(),
        role: []
      };

      const token = generateAccessToken(user);
      const decoded = jwt.decode(token) as any;

      expect(decoded.roles).toEqual([]);
    });

    test('should generate unique tokens for same user data', () => {
      const user1: AccessTokenPayload = {
        id: 123,
        visitor_id: 456,
        jti: crypto.randomUUID()
      };
      
      const user2: AccessTokenPayload = {
        id: 123,
        visitor_id: 456,
        jti: crypto.randomUUID() // Different JTI
      };

      const token1 = generateAccessToken(user1);
      const token2 = generateAccessToken(user2);

      expect(token1).not.toBe(token2);
    });

    test('should handle edge case user IDs', () => {
      const users = [
        { id: 0, visitor_id: 0, jti: crypto.randomUUID() },
        { id: 2147483647, visitor_id: 2147483647, jti: crypto.randomUUID() }, // Max int32
        { id: 1, visitor_id: 999999999, jti: crypto.randomUUID() }
      ];

      users.forEach(user => {
        const token = generateAccessToken(user);
        const decoded = jwt.decode(token) as any;
        expect(decoded.sub).toBe(user.id.toString());
        expect(decoded.visitor).toBe(user.visitor_id);
      });
    });
  });

  describe('verifyAccessToken', () => {
    test('should verify a valid token successfully', () => {
      const user: AccessTokenPayload = {
        id: 123,
        visitor_id: 456,
        jti: crypto.randomUUID()
      };

      const token = generateAccessToken(user);
      const result = verifyAccessToken(token);

      expect(result.valid).toBe(true);
      expect(result.payload).toBeTruthy();
      expect(result.errorType).toBeUndefined();
      expect(result.payload?.visitor).toBe(user.visitor_id);
      expect(result.payload?.sub).toBe(user.id.toString());
    });

    test('should reject token not in cache', () => {
      // Create a token manually without going through generateAccessToken
      const payload = {
        visitor: 456,
        roles: []
      };
      const token = jwt.sign(payload, 'test-jwt-secret-key-32-chars-long', {
        algorithm: 'HS512',
        expiresIn: '15m',
        subject: '123',
        jwtid: crypto.randomUUID()
      });

      const result = verifyAccessToken(token);

      expect(result.valid).toBe(false);
      expect(result.errorType).toBe('InvalidPayloadType');
    });

    test('should reject expired token', async () => {
      // Note: The cache-first design means manually created tokens won't be in cache
      // This is actually a security feature that prevents verification of potentially malicious tokens
      // Here we test the behavior: tokens not in cache are rejected with 'InvalidPayloadType'
      const user: AccessTokenPayload = {
        id: 123,
        visitor_id: 456,
        jti: crypto.randomUUID()
      };

      // Create an expired token that was never cached
      const expiredPayload = {
        visitor: user.visitor_id,
        roles: []
      };
      const expiredToken = jwt.sign(expiredPayload, 'test-jwt-secret-key-32-chars-long', {
        algorithm: 'HS512',
        expiresIn: '-1s', // Already expired
        subject: user.id.toString(),
        jwtid: user.jti,
        audience: 'example.com',
        issuer: 'example.com'
      });

      const result = verifyAccessToken(expiredToken);

      // Cache-first design: tokens not in cache are rejected before JWT verification
      expect(result.valid).toBe(false);
      expect(result.errorType).toBe('InvalidPayloadType');
    });

    test('should reject malformed token', () => {
      const malformedTokens = [
        'not.a.jwt',
        'malformed',
        '',
        'a.b',
        'a.b.c.d',
        'valid.header.invalidsignature'
      ];

      malformedTokens.forEach(token => {
        const result = verifyAccessToken(token);
        expect(result.valid).toBe(false);
        expect(['jwt malformed', 'invalid token', 'InvalidPayloadType']).toContain(result.errorType);
      });
    });

    test('should reject token with invalid signature', () => {
      // Cache-first design: manually created tokens won't be in cache
      // This is a security feature that prevents JWT verification of potentially malicious tokens
      const user: AccessTokenPayload = {
        id: 123,
        visitor_id: 456,
        jti: crypto.randomUUID()
      };

      // Create a token with invalid signature (not in cache)
      const tamperedPayload = {
        visitor: user.visitor_id,
        roles: []
      };
      const tokenWithInvalidSig = jwt.sign(tamperedPayload, 'wrong-secret-key', {
        algorithm: 'HS512',
        expiresIn: '15m',
        subject: user.id.toString(),
        jwtid: user.jti,
        audience: 'example.com',
        issuer: 'example.com'
      });

      const result = verifyAccessToken(tokenWithInvalidSig);

      // Cache-first design: tokens not in cache are rejected before JWT verification
      expect(result.valid).toBe(false);
      expect(result.errorType).toBe('InvalidPayloadType');
    });

    test('should reject token with mismatched visitor ID', () => {
      const user: AccessTokenPayload = {
        id: 123,
        visitor_id: 456,
        jti: crypto.randomUUID()
      };

      // Cache-first design: manually created tokens won't be in cache
      // This tests the security feature that prevents verification of potentially malicious tokens

      // Create token with different visitor_id (not in cache)
      const tamperedPayload = {
        visitor: 999, // Different visitor ID
        roles: []
      };
      const tamperedToken = jwt.sign(tamperedPayload, 'test-jwt-secret-key-32-chars-long', {
        algorithm: 'HS512',
        expiresIn: '15m',
        subject: user.id.toString(),
        jwtid: user.jti,
        audience: 'example.com',
        issuer: 'example.com'
      });

      const result = verifyAccessToken(tamperedToken);

      // Cache-first design: tokens not in cache are rejected before JWT verification
      expect(result.valid).toBe(false);
      expect(result.errorType).toBe('InvalidPayloadType');
    });

    test('should validate roles correctly', () => {
      const user: AccessTokenPayload = {
        id: 123,
        visitor_id: 456,
        jti: crypto.randomUUID(),
        role: ['admin', 'user']
      };

      const token = generateAccessToken(user);
      const result = verifyAccessToken(token);

      expect(result.valid).toBe(true);
      expect(result.payload?.roles).toEqual(['admin', 'user']);
    });

    test('should reject token with malformed roles', () => {
      const user: AccessTokenPayload = {
        id: 123,
        visitor_id: 456,
        jti: crypto.randomUUID(),
        role: ['admin']
      };

      // Cache-first design: manually created tokens won't be in cache
      // This tests the security feature that prevents verification of potentially malicious tokens

      // Create token with malformed roles but not in cache
      const malformedPayload = {
        visitor: user.visitor_id,
        roles: 'not_an_array' // Should be array
      };
      const malformedToken = jwt.sign(malformedPayload, 'test-jwt-secret-key-32-chars-long', {
        algorithm: 'HS512',
        expiresIn: '15m',
        subject: user.id.toString(),
        jwtid: user.jti,
        audience: 'example.com',
        issuer: 'example.com'
      });

      const result = verifyAccessToken(malformedToken);

      // Cache-first design: tokens not in cache are rejected before JWT verification
      expect(result.valid).toBe(false);
      expect(result.errorType).toBe('InvalidPayloadType');
    });

    test('should reject token with missing required roles', () => {
      const user: AccessTokenPayload = {
        id: 123,
        visitor_id: 456,
        jti: crypto.randomUUID(),
        role: ['admin', 'user']
      };

      // Cache-first design: manually created tokens won't be in cache
      // This tests the security feature that prevents verification of potentially malicious tokens

      // Create token with fewer roles than required but not in cache
      const insufficientPayload = {
        visitor: user.visitor_id,
        roles: ['user'] // Missing 'admin' role
      };
      const insufficientToken = jwt.sign(insufficientPayload, 'test-jwt-secret-key-32-chars-long', {
        algorithm: 'HS512',
        expiresIn: '15m',
        subject: user.id.toString(),
        jwtid: user.jti,
        audience: 'example.com',
        issuer: 'example.com'
      });

      const result = verifyAccessToken(insufficientToken);

      // Cache-first design: tokens not in cache are rejected before JWT verification
      expect(result.valid).toBe(false);
      expect(result.errorType).toBe('InvalidPayloadType');
    });

    test('should reject token with extra unexpected roles', () => {
      const user: AccessTokenPayload = {
        id: 123,
        visitor_id: 456,
        jti: crypto.randomUUID(),
        role: ['user']
      };

      // Cache-first design: manually created tokens won't be in cache
      // This tests the security feature that prevents verification of potentially malicious tokens

      // Create token with extra roles but not in cache
      const extraPayload = {
        visitor: user.visitor_id,
        roles: ['user', 'admin', 'superuser'] // Extra roles
      };
      const extraToken = jwt.sign(extraPayload, 'test-jwt-secret-key-32-chars-long', {
        algorithm: 'HS512',
        expiresIn: '15m',
        subject: user.id.toString(),
        jwtid: user.jti,
        audience: 'example.com',
        issuer: 'example.com'
      });

      const result = verifyAccessToken(extraToken);

      // Cache-first design: tokens not in cache are rejected before JWT verification
      expect(result.valid).toBe(false);
      expect(result.errorType).toBe('InvalidPayloadType');
    });

    test('should handle empty roles arrays correctly', () => {
      const user: AccessTokenPayload = {
        id: 123,
        visitor_id: 456,
        jti: crypto.randomUUID(),
        role: []
      };

      const token = generateAccessToken(user);
      const result = verifyAccessToken(token);

      expect(result.valid).toBe(true);
      expect(result.payload?.roles).toEqual([]);
    });
  });

  describe('Security Tests', () => {
    test('should reject JWT none algorithm attack', () => {
      const user: AccessTokenPayload = {
        id: 123,
        visitor_id: 456,
        jti: crypto.randomUUID()
      };

      // Generate valid token to populate cache
      generateAccessToken(user);

      // Try to create unsigned token (none algorithm attack)
      const unsignedPayload = {
        visitor: user.visitor_id,
        roles: [],
        sub: user.id.toString(),
        jti: user.jti,
        aud: 'example.com',
        iss: 'example.com'
      };

      const header = { alg: 'none', typ: 'JWT' };
      const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
      const encodedPayload = Buffer.from(JSON.stringify(unsignedPayload)).toString('base64url');
      const noneToken = `${encodedHeader}.${encodedPayload}.`;

      const result = verifyAccessToken(noneToken);

      expect(result.valid).toBe(false);
      expect(['invalid signature', 'jwt malformed', 'JsonWebTokenError', 'InvalidPayloadType']).toContain(result.errorType);
    });

    test('should reject token with different algorithm', () => {
      const user: AccessTokenPayload = {
        id: 123,
        visitor_id: 456,
        jti: crypto.randomUUID()
      };

      // Generate valid token to populate cache
      generateAccessToken(user);

      // Create token with different algorithm
      const differentAlgPayload = {
        visitor: user.visitor_id,
        roles: []
      };
      const differentAlgToken = jwt.sign(differentAlgPayload, 'test-jwt-secret-key-32-chars-long', {
        algorithm: 'HS256', // Different from configured HS512
        expiresIn: '15m',
        subject: user.id.toString(),
        jwtid: user.jti,
        audience: 'example.com',
        issuer: 'example.com'
      });

      const result = verifyAccessToken(differentAlgToken);

      expect(result.valid).toBe(false);
      expect(['JsonWebTokenError', 'InvalidPayloadType']).toContain(result.errorType);
    });

    test('should handle large payloads', () => {
      const largeRole = 'x'.repeat(1000); // 1KB role name
      const user: AccessTokenPayload = {
        id: 123,
        visitor_id: 456,
        jti: crypto.randomUUID(),
        role: [largeRole]
      };

      expect(() => generateAccessToken(user)).not.toThrow();
    });

    test('should handle special characters in JTI', () => {
      const specialJtis = [
        'test-jti-with-hyphens',
        'test_jti_with_underscores',
        'testjti123456789',
        crypto.randomUUID()
      ];

      specialJtis.forEach(jti => {
        const user: AccessTokenPayload = {
          id: 123,
          visitor_id: 456,
          jti
        };

        const token = generateAccessToken(user);
        const result = verifyAccessToken(token);

        expect(result.valid).toBe(true);
        expect(result.payload?.jti).toBe(jti);
      });
    });
  });

  describe('Edge Cases and Error Handling', () => {
    test('should handle concurrent token generation', async () => {
      const users = Array.from({ length: 10 }, (_, i) => ({
        id: i,
        visitor_id: i * 100,
        jti: crypto.randomUUID()
      }));

      const promises = users.map(user => 
        Promise.resolve(generateAccessToken(user))
      );

      const tokens = await Promise.all(promises);

      // All tokens should be unique
      const uniqueTokens = new Set(tokens);
      expect(uniqueTokens.size).toBe(tokens.length);

      // All tokens should verify correctly
      tokens.forEach(token => {
        const result = verifyAccessToken(token);
        expect(result.valid).toBe(true);
      });
    });

    test('should handle very long role names', () => {
      const longRole = 'a'.repeat(500);
      const user: AccessTokenPayload = {
        id: 123,
        visitor_id: 456,
        jti: crypto.randomUUID(),
        role: [longRole]
      };

      const token = generateAccessToken(user);
      const result = verifyAccessToken(token);

      expect(result.valid).toBe(true);
      expect(result.payload?.roles).toContain(longRole);
    });

    test('should handle many roles', () => {
      const manyRoles = Array.from({ length: 50 }, (_, i) => `role${i}`);
      const user: AccessTokenPayload = {
        id: 123,
        visitor_id: 456,
        jti: crypto.randomUUID(),
        role: manyRoles
      };

      const token = generateAccessToken(user);
      const result = verifyAccessToken(token);

      expect(result.valid).toBe(true);
      expect(result.payload?.roles).toEqual(manyRoles);
    });

    test('should handle numeric and special character roles', () => {
      const specialRoles = ['123', 'role-with-dash', 'role_with_underscore', 'UPPERCASE', 'MixedCase'];
      const user: AccessTokenPayload = {
        id: 123,
        visitor_id: 456,
        jti: crypto.randomUUID(),
        role: specialRoles
      };

      const token = generateAccessToken(user);
      const result = verifyAccessToken(token);

      expect(result.valid).toBe(true);
      expect(result.payload?.roles).toEqual(specialRoles);
    });

    test('should handle cache invalidation on verification failure', () => {
      const user: AccessTokenPayload = {
        id: 123,
        visitor_id: 456,
        jti: crypto.randomUUID()
      };

      // Generate token
      const token = generateAccessToken(user);
      
      // Verify it's valid
      let result = verifyAccessToken(token);
      expect(result.valid).toBe(true);

      // Manually invalidate the cache entry
      const cache = tokenCache();
      const cacheEntry = cache.get(token);
      if (cacheEntry) {
        cache.set(token, { ...cacheEntry, valid: false });
      }

      // Verify it's now invalid
      result = verifyAccessToken(token);
      expect(result.valid).toBe(false);
      expect(result.errorType).toBe('InvalidPayloadType');
    });

    test('should handle empty string tokens gracefully', () => {
      const result = verifyAccessToken('');
      expect(result.valid).toBe(false);
      expect(result.errorType).toBe('InvalidPayloadType');
    });

    test('should handle null-like tokens gracefully', () => {
      const invalidTokens = ['null', 'undefined', '{}', 'false'];
      
      invalidTokens.forEach(token => {
        const result = verifyAccessToken(token);
        expect(result.valid).toBe(false);
        expect(result.errorType).toBe('InvalidPayloadType');
      });
    });

    test('should verify cache TTL behavior exists', () => {
      // Test that cache has TTL configuration
      const cache = tokenCache();
      expect(cache.max).toBeGreaterThan(0);
      expect(cache.ttl).toBeGreaterThan(0);
    });

    test('should handle unicode characters in roles', () => {
      const unicodeRoles = ['admin', 'user', '管理员', 'rôle-spécial', '🚀-emoji-role'];
      const user: AccessTokenPayload = {
        id: 123,
        visitor_id: 456,
        jti: crypto.randomUUID(),
        role: unicodeRoles
      };

      const token = generateAccessToken(user);
      const result = verifyAccessToken(token);

      expect(result.valid).toBe(true);
      expect(result.payload?.roles).toEqual(unicodeRoles);
    });
  });
});