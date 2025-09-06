import mysql from 'mysql2/promise';
import mysql2 from 'mysql2';
import { configuration } from '../../src/jwtAuth/config/configuration.js';
import { vi } from 'vitest';

export let promisePool: mysql.Pool;
export let callbackPool: mysql2.Pool;

export async function setupTestDatabase() {
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
    mfa: {
      companyName: 'Test Company',
      secretKey: 'JBSWY3DPEHPK3PXP',
      codeLength: 6,
      ttlInMinutes: 5
    },
    frontend: {
      base_url: 'https://test.example.com'
    }
  });
}

export async function teardownTestDatabase() {
  if (promisePool) {
    await promisePool.end();
  }
  if (callbackPool) {
    await callbackPool.end();
  }
}

export async function setupTestUser(userId: number, visitorId: number) {
  await promisePool.execute(
    `INSERT IGNORE INTO users (id, email, password, is_verified, visitor_id) VALUES (?, ?, ?, ?, ?)`,
    [userId, `test${userId}@example.com`, 'hashed_password', 1, visitorId]
  );
  
  await promisePool.execute(
    `INSERT IGNORE INTO visitors (id, ip_address, user_agent, fingerprint, created_at) VALUES (?, ?, ?, ?, NOW())`,
    [visitorId, '192.168.1.1', 'Test-Agent/1.0', 'test-fingerprint', ]
  );
}

export async function cleanupTestData(userId: number, visitorId: number) {
  // Clean up in reverse order due to foreign key constraints
  await promisePool.execute(`DELETE FROM refresh_tokens WHERE user_id = ?`, [userId]);
  await promisePool.execute(`DELETE FROM user_sessions WHERE user_id = ?`, [userId]);
  await promisePool.execute(`DELETE FROM mfa_codes WHERE user_id = ?`, [userId]);
  await promisePool.execute(`DELETE FROM temp_links WHERE user_id = ?`, [userId]);
  await promisePool.execute(`DELETE FROM anomalies WHERE user_id = ?`, [userId]);
  await promisePool.execute(`DELETE FROM users WHERE id = ?`, [userId]);
  await promisePool.execute(`DELETE FROM visitors WHERE id = ?`, [visitorId]);
}

// Mock bot detector for controlled testing
export const mockBotDetector = () => {
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
};