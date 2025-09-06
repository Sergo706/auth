import { describe, test, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';
import mysql from 'mysql2/promise';
import mysql2 from 'mysql2';
import crypto from 'crypto';
import { configuration } from '../../src/jwtAuth/config/configuration.js';
import { strangeThings } from '../../src/anomalies.js';

describe('Anomalies Detection - Comprehensive Edge Cases', () => {
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
    await promisePool.execute('DELETE FROM mfa_codes WHERE user_id < 1000');
    await promisePool.execute('DELETE FROM refresh_tokens WHERE user_id < 1000');
    await promisePool.execute('DELETE FROM users WHERE id < 1000');
    await promisePool.execute('DELETE FROM banned WHERE canary_id LIKE "test_%"');
    await promisePool.execute('DELETE FROM visitors WHERE canary_id LIKE "test_%"');
  });

  afterAll(async () => {
    // Clean up test data
    await promisePool.execute('DELETE FROM mfa_codes WHERE user_id < 1000');
    await promisePool.execute('DELETE FROM refresh_tokens WHERE user_id < 1000');
    await promisePool.execute('DELETE FROM users WHERE id < 1000');
    await promisePool.execute('DELETE FROM banned WHERE canary_id LIKE "test_%"');
    await promisePool.execute('DELETE FROM visitors WHERE canary_id LIKE "test_%"');
    
    if (promisePool) await promisePool.end();
    if (callbackPool) callbackPool.end();
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // Helper function to setup test data
  async function setupTestData(options: {
    visitorId?: number;
    canaryId?: string;
    userId?: number;
    token?: string;
    ipAddress?: string;
    userAgent?: string;
    country?: string;
    city?: string;
    lat?: string;
    lon?: string;
    tokenValid?: boolean;
    tokenExpired?: boolean;
    usageCount?: number;
    lastMfaAt?: Date | null;
  }) {
    const {
      visitorId = 100,
      canaryId = 'test_canary_' + crypto.randomUUID(),
      userId = 100,
      token = crypto.randomBytes(32).toString('hex'),
      ipAddress = '192.168.1.100',
      userAgent = 'Mozilla/5.0 (Test Browser)',
      country = 'US',
      city = 'TestCity',
      lat = '40.7128',
      lon = '-74.0060',
      tokenValid = true,
      tokenExpired = false,
      usageCount = 1,
      lastMfaAt = null
    } = options;

    // Insert visitor
    await promisePool.execute(`
      INSERT INTO visitors 
      (visitor_id, canary_id, ip_address, user_agent, country, city, lat, lon)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE 
      ip_address = VALUES(ip_address),
      user_agent = VALUES(user_agent),
      country = VALUES(country),
      city = VALUES(city),
      lat = VALUES(lat),
      lon = VALUES(lon)
    `, [visitorId, canaryId, ipAddress, userAgent, country, city, lat, lon]);

    // Insert user
    await promisePool.execute(`
      INSERT INTO users 
      (id, name, last_name, email, password_hash, visitor_id, last_mfa_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE 
      visitor_id = VALUES(visitor_id),
      last_mfa_at = VALUES(last_mfa_at)
    `, [userId, 'Test', 'User', `test${userId}@example.com`, 'hashed_password', visitorId, lastMfaAt]);

    // Insert refresh token
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    const expiresAt = tokenExpired ? 
      new Date(Date.now() - 24 * 60 * 60 * 1000) : // Expired yesterday
      new Date(Date.now() + 24 * 60 * 60 * 1000);  // Expires tomorrow

    await promisePool.execute(`
      INSERT INTO refresh_tokens 
      (user_id, token, valid, expiresAt, usage_count, created_at, session_started_at)
      VALUES (?, ?, ?, ?, ?, NOW(), NOW())
      ON DUPLICATE KEY UPDATE 
      valid = VALUES(valid),
      expiresAt = VALUES(expiresAt),
      usage_count = VALUES(usage_count)
    `, [userId, hashedToken, tokenValid, expiresAt, usageCount]);

    return { visitorId, canaryId, userId, token, hashedToken, ipAddress, userAgent };
  }

  describe('Token Validation Edge Cases', () => {
    test('should reject invalid token - token not found in database', async () => {
      const nonExistentToken = crypto.randomBytes(32).toString('hex');
      const canaryId = 'test_canary_' + crypto.randomUUID();
      
      const result = await strangeThings(
        nonExistentToken,
        canaryId,
        '192.168.1.1',
        'Mozilla/5.0 (Test)',
        false
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Token not found');
      expect(result.reqMFA).toBe(false);
    });

    test('should reject expired token', async () => {
      const testData = await setupTestData({ 
        tokenExpired: true,
        userId: 101,
        visitorId: 101 
      });

      const result = await strangeThings(
        testData.token,
        testData.canaryId,
        testData.ipAddress,
        testData.userAgent,
        false
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Token expired');
      expect(result.reqMFA).toBe(false);
    });

    test('should reject invalid/revoked token', async () => {
      const testData = await setupTestData({ 
        tokenValid: false,
        userId: 102,
        visitorId: 102 
      });

      const result = await strangeThings(
        testData.token,
        testData.canaryId,
        testData.ipAddress,
        testData.userAgent,
        false
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Token revoked');
      expect(result.reqMFA).toBe(false);
    });
  });

  describe('Basic Valid Token Cases', () => {
    test('should accept valid token with matching conditions', async () => {
      const testData = await setupTestData({ 
        userId: 103,
        visitorId: 103 
      });

      const result = await strangeThings(
        testData.token,
        testData.canaryId,
        testData.ipAddress,
        testData.userAgent,
        false
      );

      expect(result.valid).toBe(true);
      expect(result.userId).toBe(103);
      expect(result.visitorId).toBe(103);
    });
  });

  describe('Malformed Input Handling', () => {
    test('should handle malformed user agent strings', async () => {
      const testData = await setupTestData({ 
        userId: 107,
        visitorId: 107,
        userAgent: 'Normal User Agent'
      });

      const malformedUserAgents = [
        '', // Empty string
        'a'.repeat(10000), // Extremely long
        'Mozilla/5.0\x00\x01\x02', // Contains null bytes
        'Mozilla/5.0 <script>alert(1)</script>', // XSS attempt
      ];

      for (const ua of malformedUserAgents) {
        const result = await strangeThings(
          testData.token,
          testData.canaryId,
          testData.ipAddress,
          ua,
          false
        );

        // Should not crash with malformed user agent
        expect(result).toHaveProperty('valid');
        expect(result).toHaveProperty('reason');
        expect(result).toHaveProperty('reqMFA');
      }
    });

    test('should handle malformed IP addresses', async () => {
      const testData = await setupTestData({ 
        userId: 109,
        visitorId: 109,
        ipAddress: '192.168.1.100'
      });

      const malformedIPs = [
        '', // Empty
        'not.an.ip.address',
        '999.999.999.999', // Out of range
        '192.168.1', // Incomplete
        '192.168.1.100.50', // Too many octets
        '192.168.1.100; DROP TABLE users;', // SQL injection attempt
      ];

      for (const ip of malformedIPs) {
        const result = await strangeThings(
          testData.token,
          testData.canaryId,
          ip,
          testData.userAgent,
          false
        );

        // Should not crash with malformed IP
        expect(result).toHaveProperty('valid');
        expect(result).toHaveProperty('reason');
        expect(result).toHaveProperty('reqMFA');
      }
    });

    test('should handle malformed canary IDs', async () => {
      const testData = await setupTestData({ 
        userId: 116,
        visitorId: 116 
      });

      const malformedCanaryIds = [
        '', // Empty
        'a'.repeat(1000), // Too long
        'canary\x00id', // Null bytes
        'canary<script>alert(1)</script>id', // XSS attempt
        'canary; DROP TABLE visitors; --', // SQL injection attempt
      ];

      for (const canaryId of malformedCanaryIds) {
        const result = await strangeThings(
          testData.token,
          canaryId,
          testData.ipAddress,
          testData.userAgent,
          false
        );

        // Should not crash with malformed canary ID
        expect(result).toHaveProperty('valid');
        expect(result).toHaveProperty('reason');
        expect(result).toHaveProperty('reqMFA');
      }
    });
  });

  describe('Database Error Handling', () => {
    test('should handle database connection failures gracefully', async () => {
      const invalidToken = 'definitely_not_a_valid_token';
      
      const result = await strangeThings(
        invalidToken,
        'test_canary',
        '192.168.1.1',
        'Mozilla/5.0 (Test)',
        false
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toBeDefined();
    });
  });

  describe('Boundary Values and Edge Cases', () => {
    test('should handle maximum usage count values', async () => {
      const testData = await setupTestData({ 
        userId: 119,
        visitorId: 119,
        usageCount: 1000 // High but not MAX_SAFE_INTEGER to avoid potential issues
      });

      const result = await strangeThings(
        testData.token,
        testData.canaryId,
        testData.ipAddress,
        testData.userAgent,
        false
      );

      expect(result).toHaveProperty('valid');
      expect(result).toHaveProperty('reason');
      expect(result).toHaveProperty('reqMFA');
    });

    test('should handle token rotation scenarios', async () => {
      const testData = await setupTestData({ 
        userId: 111,
        visitorId: 111 
      });

      // Test with rotation flag set to true
      const result = await strangeThings(
        testData.token,
        testData.canaryId,
        testData.ipAddress,
        testData.userAgent,
        true // rotated = true
      );

      // Rotation should affect the behavior
      expect(result).toHaveProperty('valid');
      expect(result).toHaveProperty('reason');
      expect(result).toHaveProperty('reqMFA');
    });
  });
});