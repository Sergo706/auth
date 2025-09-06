import { beforeAll, afterAll, beforeEach, vi, afterEach } from 'vitest';
import mysql from 'mysql2/promise';
import mysql2 from 'mysql2';
import { configuration } from '../../src/jwtAuth/config/configuration.js';
import { tokenCache } from '../../src/jwtAuth/utils/accessTokentCache.js';

export let promisePool: mysql.Pool;
export let callbackPool: mysql2.Pool;

beforeAll(async () => {
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
  if (promisePool) {
    await promisePool.end();
  }
  if (callbackPool) {
    callbackPool.end();
  }
});

beforeEach(() => {
  vi.useFakeTimers().setSystemTime(new Date(1_700_000_000_000));
  vi.clearAllMocks();
});


afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});


beforeEach(() => {
  const cache = tokenCache();
  if (typeof (cache as any).clear === 'function') {
    (cache as any).clear();
  } else {
    if (typeof (cache as any).keys === 'function') {
      for (const k of (cache as any).keys()) {
        (cache as any).delete(k);
      }
    }
  }
});
