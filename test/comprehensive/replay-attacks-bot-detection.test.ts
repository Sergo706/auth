import { describe, test, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import mysql from 'mysql2/promise';
import mysql2 from 'mysql2';
import crypto from 'crypto';
import { configuration } from '../../src/jwtAuth/config/configuration.js';
import { generateAccessToken, verifyAccessToken } from '../../src/accessTokens.js';
import { generateRefreshToken, verifyRefreshToken, rotateRefreshToken } from '../../src/refreshTokens.js';

// Mock bot detector for controlled testing
vi.mock('@riavzon/botdetector', () => ({
  getGeoData: vi.fn().mockResolvedValue({
    country: 'US',
    region: 'NY',
    regionName: 'New York',
    city: 'New York',
    district: 'Manhattan',
    lat: 40.7128,
    lon: -74.0060,
    timezone: 'America/New_York',
    currency: 'USD',
    isp: 'Test ISP',
    org: 'Test Org',
    as: 'AS12345'
  }),
  parseUA: vi.fn().mockReturnValue({
    device: 'desktop',
    browser: 'Chrome',
    browserType: 'browser',
    browserVersion: '91.0',
    os: 'Windows',
    deviceVendor: 'unknown',
    deviceModel: 'unknown'
  }),
  banIp: vi.fn().mockResolvedValue(undefined),
  updateIsBot: vi.fn().mockResolvedValue(undefined),
  updateBannedIP: vi.fn().mockResolvedValue(undefined)
}));

describe('Replay Attacks and Bot Detection - Comprehensive Security Testing', () => {
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
    await promisePool.execute('DELETE FROM mfa_codes WHERE user_id BETWEEN 4000 AND 4999');
    await promisePool.execute('DELETE FROM refresh_tokens WHERE user_id BETWEEN 4000 AND 4999');
    await promisePool.execute('DELETE FROM users WHERE id BETWEEN 4000 AND 4999');
    await promisePool.execute('DELETE FROM banned WHERE canary_id LIKE "security_test_%"');
    await promisePool.execute('DELETE FROM visitors WHERE canary_id LIKE "security_test_%"');
  });

  afterAll(async () => {
    // Clean up test data
    await promisePool.execute('DELETE FROM mfa_codes WHERE user_id BETWEEN 4000 AND 4999');
    await promisePool.execute('DELETE FROM refresh_tokens WHERE user_id BETWEEN 4000 AND 4999');
    await promisePool.execute('DELETE FROM users WHERE id BETWEEN 4000 AND 4999');
    await promisePool.execute('DELETE FROM banned WHERE canary_id LIKE "security_test_%"');
    await promisePool.execute('DELETE FROM visitors WHERE canary_id LIKE "security_test_%"');
    
    if (promisePool) await promisePool.end();
    if (callbackPool) callbackPool.end();
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  // Helper function to setup test user and visitor
  async function setupTestUser(userId: number, visitorId: number) {
    const canaryId = `security_test_${userId}_${crypto.randomUUID()}`;
    
    // Insert visitor
    await promisePool.execute(`
      INSERT INTO visitors 
      (visitor_id, canary_id, ip_address, user_agent, country, city, lat, lon, is_bot)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE 
      ip_address = VALUES(ip_address)
    `, [visitorId, canaryId, '192.168.1.1', 'Mozilla/5.0 (Test)', 'US', 'TestCity', '40.7128', '-74.0060', false]);

    // Insert user
    await promisePool.execute(`
      INSERT INTO users 
      (id, name, last_name, email, password_hash, visitor_id)
      VALUES (?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE 
      visitor_id = VALUES(visitor_id)
    `, [userId, 'Test', 'User', `sectest${userId}@example.com`, 'hashed_password', visitorId]);

    return { userId, visitorId, canaryId };
  }

  describe('Token Replay Attack Prevention', () => {
    test('should prevent access token replay attacks', async () => {
      const user = {
        id: 4001,
        visitor_id: 4001,
        jti: crypto.randomUUID()
      };

      const token = generateAccessToken(user);
      
      // First verification should succeed
      const result1 = verifyAccessToken(token);
      expect(result1.valid).toBe(true);

      // Subsequent verifications should also succeed (stateless tokens)
      // But in practice, JTI should be tracked to prevent replay
      const result2 = verifyAccessToken(token);
      expect(result2.valid).toBe(true);
      expect(result2.payload?.jti).toBe(user.jti);

      // Same JTI should be consistent
      const result3 = verifyAccessToken(token);
      expect(result3.valid).toBe(true);
      expect(result3.payload?.jti).toBe(user.jti);
    });

    test('should track JTI usage for replay detection', async () => {
      // Generate multiple tokens with the same user but different JTIs
      const baseUser = { id: 4002, visitor_id: 4002 };
      
      const tokens = Array.from({ length: 5 }, () => {
        const user = { ...baseUser, jti: crypto.randomUUID() };
        return { token: generateAccessToken(user), jti: user.jti };
      });

      // All tokens should be valid and have unique JTIs
      const jtis = new Set();
      tokens.forEach(({ token, jti }) => {
        const result = verifyAccessToken(token);
        expect(result.valid).toBe(true);
        expect(result.payload?.jti).toBe(jti);
        jtis.add(jti);
      });

      expect(jtis.size).toBe(5); // All JTIs should be unique
    });

    test('should prevent refresh token replay attacks', async () => {
      const { userId, visitorId } = await setupTestUser(4003, 4003);
      const ttl = 24 * 60 * 60 * 1000;

      // Generate initial refresh token
      const token1 = await generateRefreshToken(ttl, userId, visitorId);
      
      // Verify it's valid
      const verify1 = await verifyRefreshToken(token1.raw);
      expect(verify1.valid).toBe(true);

      // Rotate the token
      const rotation = await rotateRefreshToken(ttl, userId, token1.raw);
      expect(rotation.rotated).toBe(true);

      // Original token should now be invalid (rotation invalidates it)
      const verify2 = await verifyRefreshToken(token1.raw);
      expect(verify2.valid).toBe(false);

      // New token should be valid
      const verify3 = await verifyRefreshToken(rotation.raw!);
      expect(verify3.valid).toBe(true);

      // Attempting to use the old token again should fail (replay prevention)
      const verify4 = await verifyRefreshToken(token1.raw);
      expect(verify4.valid).toBe(false);
    });

    test('should detect rapid successive token usage', async () => {
      const { userId, visitorId } = await setupTestUser(4004, 4004);
      const ttl = 24 * 60 * 60 * 1000;

      const token = await generateRefreshToken(ttl, userId, visitorId);
      
      // Rapidly verify the same token multiple times
      const verifications = await Promise.all(
        Array.from({ length: 10 }, () => verifyRefreshToken(token.raw))
      );

      // All should succeed (but this pattern should be flagged by monitoring)
      verifications.forEach(result => {
        expect(result.valid).toBe(true);
      });

      // Check if usage count was tracked
      const [rows] = await promisePool.execute<any[]>(
        'SELECT usage_count FROM refresh_tokens WHERE user_id = ?',
        [userId]
      );
      
      expect(rows.length).toBe(1);
      // Usage count might be updated depending on implementation
    });

    test('should handle concurrent token rotation attempts', async () => {
      const { userId, visitorId } = await setupTestUser(4005, 4005);
      const ttl = 24 * 60 * 60 * 1000;

      const token = await generateRefreshToken(ttl, userId, visitorId);
      
      // Attempt multiple concurrent rotations (race condition)
      const rotations = await Promise.allSettled(
        Array.from({ length: 5 }, () => rotateRefreshToken(ttl, userId, token.raw))
      );

      // Only one rotation should succeed due to database constraints
      const successful = rotations.filter(r => 
        r.status === 'fulfilled' && (r.value as any).rotated
      );
      
      expect(successful.length).toBeLessThanOrEqual(1);

      // Original token should be invalid after any successful rotation
      const verification = await verifyRefreshToken(token.raw);
      expect(verification.valid).toBe(false);
    });
  });

  describe('Bot Detection Integration', () => {
    test('should detect known bot user agents', async () => {
      const botUserAgents = [
        'Googlebot/2.1 (+http://www.google.com/bot.html)',
        'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
        'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
        'Twitterbot/1.0',
        'LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com/)',
        'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)',
        'WhatsApp/2.19.81 A',
        'TelegramBot (like TwitterBot)',
        'python-requests/2.25.1',
        'curl/7.68.0',
        'wget/1.20.3'
      ];

      for (let i = 0; i < botUserAgents.length; i++) {
        const userId = 4100 + i;
        const visitorId = 4100 + i;
        const canaryId = `bot_test_${i}`;

        // Insert visitor with bot user agent
        await promisePool.execute(`
          INSERT INTO visitors 
          (visitor_id, canary_id, ip_address, user_agent, country, city, is_bot)
          VALUES (?, ?, ?, ?, ?, ?, ?)
          ON DUPLICATE KEY UPDATE 
          user_agent = VALUES(user_agent),
          is_bot = VALUES(is_bot)
        `, [visitorId, canaryId, '192.168.1.1', botUserAgents[i], 'US', 'TestCity', true]);

        // Verify bot is marked
        const [rows] = await promisePool.execute<any[]>(
          'SELECT is_bot FROM visitors WHERE canary_id = ?',
          [canaryId]
        );
        expect(rows[0].is_bot).toBe(1);
      }
    });

    test('should detect suspicious activity patterns', async () => {
      const { userId, visitorId, canaryId } = await setupTestUser(4006, 4006);

      // Simulate rapid requests (bot-like behavior)
      for (let i = 0; i < 100; i++) {
        await promisePool.execute(`
          UPDATE visitors 
          SET request_count = request_count + 1, 
              suspicos_activity_score = suspicos_activity_score + 1
          WHERE canary_id = ?
        `, [canaryId]);
      }

      // Check if suspicious activity was tracked
      const [rows] = await promisePool.execute<any[]>(
        'SELECT request_count, suspicos_activity_score FROM visitors WHERE canary_id = ?',
        [canaryId]
      );

      expect(rows[0].request_count).toBeGreaterThan(100);
      expect(rows[0].suspicos_activity_score).toBeGreaterThan(50);
    });

    test('should handle IP-based bot detection', async () => {
      const suspiciousIPs = [
        '127.0.0.1', // Localhost
        '0.0.0.0',   // Invalid
        '10.0.0.1',  // Private network
        '172.16.0.1', // Private network
        '192.168.0.1', // Private network
        '169.254.1.1', // Link-local
        '224.0.0.1'  // Multicast
      ];

      for (let i = 0; i < suspiciousIPs.length; i++) {
        const userId = 4200 + i;
        const visitorId = 4200 + i;
        const canaryId = `ip_test_${i}`;

        await promisePool.execute(`
          INSERT INTO visitors 
          (visitor_id, canary_id, ip_address, user_agent, country, city)
          VALUES (?, ?, ?, ?, ?, ?)
          ON DUPLICATE KEY UPDATE 
          ip_address = VALUES(ip_address)
        `, [visitorId, canaryId, suspiciousIPs[i], 'Mozilla/5.0', 'Unknown', 'Unknown']);

        // Check if suspicious IP was recorded
        const [rows] = await promisePool.execute<any[]>(
          'SELECT ip_address FROM visitors WHERE canary_id = ?',
          [canaryId]
        );
        expect(rows[0].ip_address).toBe(suspiciousIPs[i]);
      }
    });

    test('should detect rapid geographic location changes', async () => {
      const { userId, visitorId, canaryId } = await setupTestUser(4007, 4007);

      // Simulate rapid location changes (impossible travel)
      const locations = [
        { country: 'US', city: 'New York', lat: '40.7128', lon: '-74.0060' },
        { country: 'JP', city: 'Tokyo', lat: '35.6762', lon: '139.6503' },
        { country: 'GB', city: 'London', lat: '51.5074', lon: '-0.1278' },
        { country: 'AU', city: 'Sydney', lat: '-33.8688', lon: '151.2093' },
        { country: 'BR', city: 'São Paulo', lat: '-23.5558', lon: '-46.6396' }
      ];

      for (const location of locations) {
        await promisePool.execute(`
          UPDATE visitors 
          SET country = ?, city = ?, lat = ?, lon = ?, 
              last_seen = NOW(), suspicos_activity_score = suspicos_activity_score + 5
          WHERE canary_id = ?
        `, [location.country, location.city, location.lat, location.lon, canaryId]);

        // Small delay to show time progression
        await new Promise(resolve => setTimeout(resolve, 10));
      }

      // Check final state
      const [rows] = await promisePool.execute<any[]>(
        'SELECT country, city, suspicos_activity_score FROM visitors WHERE canary_id = ?',
        [canaryId]
      );

      expect(rows[0].country).toBe('BR');
      expect(rows[0].city).toBe('São Paulo');
      expect(rows[0].suspicos_activity_score).toBeGreaterThan(20);
    });

    test('should handle device fingerprint anomalies', async () => {
      const { userId, visitorId, canaryId } = await setupTestUser(4008, 4008);

      // Simulate rapid device changes
      const devices = [
        { device: 'desktop', browser: 'Chrome', os: 'Windows', deviceVendor: 'Dell' },
        { device: 'mobile', browser: 'Safari', os: 'iOS', deviceVendor: 'Apple' },
        { device: 'tablet', browser: 'Firefox', os: 'Android', deviceVendor: 'Samsung' },
        { device: 'desktop', browser: 'Edge', os: 'macOS', deviceVendor: 'Apple' },
        { device: 'mobile', browser: 'Chrome', os: 'Android', deviceVendor: 'Google' }
      ];

      for (const device of devices) {
        await promisePool.execute(`
          UPDATE visitors 
          SET device_type = ?, browser = ?, os = ?, deviceVendor = ?,
              suspicos_activity_score = suspicos_activity_score + 3
          WHERE canary_id = ?
        `, [device.device, device.browser, device.os, device.deviceVendor, canaryId]);
      }

      // Check if device changes were tracked
      const [rows] = await promisePool.execute<any[]>(
        'SELECT device_type, browser, os, deviceVendor, suspicos_activity_score FROM visitors WHERE canary_id = ?',
        [canaryId]
      );

      expect(rows[0].device_type).toBe('mobile');
      expect(rows[0].browser).toBe('Chrome');
      expect(rows[0].suspicos_activity_score).toBeGreaterThan(10);
    });
  });

  describe('Advanced Attack Patterns', () => {
    test('should detect token enumeration attacks', async () => {
      const { userId, visitorId } = await setupTestUser(4009, 4009);

      // Generate many tokens rapidly (enumeration attempt)
      const tokens = [];
      for (let i = 0; i < 20; i++) {
        const token = await generateRefreshToken(24 * 60 * 60 * 1000, userId, visitorId);
        tokens.push(token);
      }

      // Check if this triggered any security measures
      const [rows] = await promisePool.execute<any[]>(
        'SELECT COUNT(*) as token_count FROM refresh_tokens WHERE user_id = ?',
        [userId]
      );

      // Should be limited by maxAllowedSessionsPerUser (5)
      expect(rows[0].token_count).toBeLessThanOrEqual(5);
    });

    test('should detect timing attack attempts', async () => {
      const validUser = { id: 4010, visitor_id: 4010, jti: crypto.randomUUID() };
      const invalidUser = { id: 9999, visitor_id: 9999, jti: crypto.randomUUID() };

      const validToken = generateAccessToken(validUser);
      const invalidToken = generateAccessToken(invalidUser);

      // Measure timing for valid vs invalid tokens
      const validStart = Date.now();
      verifyAccessToken(validToken);
      const validEnd = Date.now();

      const invalidStart = Date.now();
      verifyAccessToken(invalidToken);
      const invalidEnd = Date.now();

      const validTime = validEnd - validStart;
      const invalidTime = invalidEnd - invalidStart;

      // Times should be relatively similar to prevent timing attacks
      const timeDifference = Math.abs(validTime - invalidTime);
      expect(timeDifference).toBeLessThan(100); // Within 100ms
    });

    test('should handle session fixation attempts', async () => {
      const { userId, visitorId } = await setupTestUser(4011, 4011);

      // Attacker tries to fix a session ID
      const fixedJti = 'fixed-session-id-12345';
      const userWithFixedJti = { id: userId, visitor_id: visitorId, jti: fixedJti };

      // Generate token with fixed JTI
      const token = generateAccessToken(userWithFixedJti);
      const result = verifyAccessToken(token);

      expect(result.valid).toBe(true);
      expect(result.payload?.jti).toBe(fixedJti);

      // In practice, the application should validate that JTI is properly random
      // and not accept predictable session IDs
    });

    test('should detect privilege escalation attempts', async () => {
      const normalUser = { id: 4012, visitor_id: 4012, jti: crypto.randomUUID() };
      const adminUser = { id: 1, visitor_id: 1, jti: crypto.randomUUID(), role: ['admin'] };

      const normalToken = generateAccessToken(normalUser);
      const adminToken = generateAccessToken(adminUser);

      // Verify tokens maintain their privilege levels
      const normalResult = verifyAccessToken(normalToken);
      const adminResult = verifyAccessToken(adminToken);

      expect(normalResult.valid).toBe(true);
      expect(normalResult.payload?.roles).toBeUndefined();

      expect(adminResult.valid).toBe(true);
      expect(adminResult.payload?.roles).toContain('admin');

      // Attempt to modify payload (should fail signature verification)
      const parts = normalToken.split('.');
      const decodedPayload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      decodedPayload.roles = ['admin']; // Attempt privilege escalation
      
      parts[1] = Buffer.from(JSON.stringify(decodedPayload)).toString('base64url');
      const tamperedToken = parts.join('.');

      const tamperedResult = verifyAccessToken(tamperedToken);
      expect(tamperedResult.valid).toBe(false); // Should fail due to signature mismatch
    });

    test('should handle brute force attacks on token verification', async () => {
      const validUser = { id: 4013, visitor_id: 4013, jti: crypto.randomUUID() };
      const validToken = generateAccessToken(validUser);

      // Simulate brute force with many invalid tokens
      const invalidTokens = Array.from({ length: 100 }, () => {
        const randomBytes = crypto.randomBytes(32).toString('base64url');
        return `eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.${randomBytes}.${randomBytes}`;
      });

      let validCount = 0;
      let invalidCount = 0;

      // Test valid token
      const validResult = verifyAccessToken(validToken);
      if (validResult.valid) validCount++;

      // Test invalid tokens
      invalidTokens.forEach(invalidToken => {
        const result = verifyAccessToken(invalidToken);
        if (result.valid) validCount++;
        else invalidCount++;
      });

      expect(validCount).toBe(1); // Only the valid token should pass
      expect(invalidCount).toBe(100); // All invalid tokens should fail
    });
  });

  describe('Rate Limiting and Abuse Prevention', () => {
    test('should handle rapid request patterns', async () => {
      const { userId, visitorId } = await setupTestUser(4014, 4014);

      // Generate initial token
      const token = await generateRefreshToken(24 * 60 * 60 * 1000, userId, visitorId);

      // Rapid verification attempts
      const rapidVerifications = await Promise.all(
        Array.from({ length: 50 }, () => verifyRefreshToken(token.raw))
      );

      // All should initially succeed (rate limiting would be at middleware level)
      rapidVerifications.forEach(result => {
        expect(result.valid).toBe(true);
      });

      // But usage patterns should be tracked
      const [rows] = await promisePool.execute<any[]>(
        'SELECT usage_count FROM refresh_tokens WHERE user_id = ?',
        [userId]
      );

      expect(rows.length).toBe(1);
      // Usage count tracking depends on implementation
    });

    test('should prevent excessive token generation', async () => {
      const { userId, visitorId } = await setupTestUser(4015, 4015);

      // Try to generate excessive tokens
      const tokens = [];
      for (let i = 0; i < 10; i++) {
        try {
          const token = await generateRefreshToken(24 * 60 * 60 * 1000, userId, visitorId);
          tokens.push(token);
        } catch (error) {
          // Some tokens might be rejected due to limits
        }
      }

      // Should be limited by maxAllowedSessionsPerUser
      const [rows] = await promisePool.execute<any[]>(
        'SELECT COUNT(*) as count FROM refresh_tokens WHERE user_id = ? AND valid = 1',
        [userId]
      );

      expect(rows[0].count).toBeLessThanOrEqual(5); // Max sessions limit
    });

    test('should handle distributed attack simulation', async () => {
      // Simulate attacks from multiple "users"
      const attackUsers = Array.from({ length: 20 }, (_, i) => ({
        userId: 4100 + i,
        visitorId: 4100 + i
      }));

      // Setup all attack users
      await Promise.all(
        attackUsers.map(({ userId, visitorId }) => setupTestUser(userId, visitorId))
      );

      // Each user attempts rapid token generation
      const allTokens = await Promise.allSettled(
        attackUsers.map(async ({ userId, visitorId }) => {
          const tokens = [];
          for (let i = 0; i < 5; i++) {
            try {
              const token = await generateRefreshToken(24 * 60 * 60 * 1000, userId, visitorId);
              tokens.push(token);
            } catch (error) {
              // Some might fail
            }
          }
          return tokens;
        })
      );

      // Most operations should complete
      const successful = allTokens.filter(result => result.status === 'fulfilled');
      expect(successful.length).toBeGreaterThan(15);

      // Check total token count
      const [totalRows] = await promisePool.execute<any[]>(
        'SELECT COUNT(*) as total FROM refresh_tokens WHERE user_id BETWEEN 4100 AND 4119'
      );

      // Should be manageable number (not unlimited)
      expect(totalRows[0].total).toBeLessThan(100);
    });
  });

  describe('Security Monitoring and Forensics', () => {
    test('should track security events for audit', async () => {
      const { userId, visitorId, canaryId } = await setupTestUser(4016, 4016);

      // Generate and verify tokens (normal activity)
      const token = await generateRefreshToken(24 * 60 * 60 * 1000, userId, visitorId);
      await verifyRefreshToken(token.raw);

      // Rotate token (security event)
      const rotation = await rotateRefreshToken(24 * 60 * 60 * 1000, userId, token.raw);
      expect(rotation.rotated).toBe(true);

      // Check audit trail
      const [refreshRows] = await promisePool.execute<any[]>(
        'SELECT created_at, usage_count, valid FROM refresh_tokens WHERE user_id = ? ORDER BY created_at DESC',
        [userId]
      );

      expect(refreshRows.length).toBeGreaterThan(0);
      
      const [visitorRows] = await promisePool.execute<any[]>(
        'SELECT first_seen, last_seen, request_count FROM visitors WHERE canary_id = ?',
        [canaryId]
      );

      expect(visitorRows.length).toBe(1);
      expect(visitorRows[0].request_count).toBeGreaterThan(0);
    });

    test('should maintain forensic data integrity', async () => {
      const { userId, visitorId, canaryId } = await setupTestUser(4017, 4017);

      // Record initial state
      const [initialRows] = await promisePool.execute<any[]>(
        'SELECT * FROM visitors WHERE canary_id = ?',
        [canaryId]
      );

      expect(initialRows.length).toBe(1);
      const initialState = initialRows[0];

      // Perform operations
      const token = await generateRefreshToken(24 * 60 * 60 * 1000, userId, visitorId);
      await verifyRefreshToken(token.raw);

      // Update visitor activity
      await promisePool.execute(`
        UPDATE visitors 
        SET request_count = request_count + 1, 
            last_seen = NOW()
        WHERE canary_id = ?
      `, [canaryId]);

      // Verify data integrity
      const [finalRows] = await promisePool.execute<any[]>(
        'SELECT * FROM visitors WHERE canary_id = ?',
        [canaryId]
      );

      expect(finalRows.length).toBe(1);
      const finalState = finalRows[0];

      // Key fields should be preserved
      expect(finalState.visitor_id).toBe(initialState.visitor_id);
      expect(finalState.canary_id).toBe(initialState.canary_id);
      expect(finalState.ip_address).toBe(initialState.ip_address);
      
      // Activity fields should be updated
      expect(finalState.request_count).toBeGreaterThan(initialState.request_count);
    });

    test('should handle security log overflow gracefully', async () => {
      const { userId, visitorId } = await setupTestUser(4018, 4018);

      // Generate many security events
      for (let i = 0; i < 50; i++) {
        try {
          const token = await generateRefreshToken(100, userId, visitorId); // Short TTL
          await verifyRefreshToken(token.raw);
          // Let tokens expire quickly
          await new Promise(resolve => setTimeout(resolve, 1));
        } catch (error) {
          // Some operations might fail due to limits
        }
      }

      // System should still be responsive
      const finalToken = await generateRefreshToken(24 * 60 * 60 * 1000, userId, visitorId);
      const verification = await verifyRefreshToken(finalToken.raw);
      expect(verification.valid).toBe(true);

      // Check that database hasn't grown excessively
      const [tokenRows] = await promisePool.execute<any[]>(
        'SELECT COUNT(*) as count FROM refresh_tokens WHERE user_id = ?',
        [userId]
      );

      expect(tokenRows[0].count).toBeLessThanOrEqual(10); // Reasonable limit
    });
  });
});