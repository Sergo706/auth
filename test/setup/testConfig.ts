import mysql from 'mysql2';
import mysql2 from 'mysql2/promise';
import { configuration } from '../../src/jwtAuth/config/configuration.js';
import 'dotenv/config';

const TEST_DB_CONFIG = {
  host: process.env.DB_HOST!,
  port: Number(process.env.DB_PORT!),
  user: process.env.DB_USER!,
  password: process.env.DB_PASS!,
  database: process.env.DB_NAME!,
  multipleStatements: true
};


let pools: { mainPool: mysql2.Pool; rateLimiterPool: mysql.Pool } | null = null;

export function createTestPools() {
  console.log(process.env.VITE_DB_HOST)
    console.log('Creating test pools');
  if (!pools) {
    pools = {
      mainPool: mysql2.createPool({
        ...TEST_DB_CONFIG,
        waitForConnections: true,
        connectionLimit: 5,
        queueLimit: 0,
      }),
      rateLimiterPool: mysql.createPool({
        ...TEST_DB_CONFIG,
        waitForConnections: true,
        connectionLimit: 5,
        queueLimit: 0
      })
    };
    console.log('New pools created');
  }  else {
    console.log('Reusing existing pools');
  }
  return pools;
}

export async function closeTestPools() {
   console.log('Closing test pools');
  if (pools) {
    await pools.mainPool.end();
    pools.rateLimiterPool.end();
    pools = null;
    console.log('Pools closed');
  } else {
    console.log('No pools to close');
  }
}

export function setupTestConfiguration() {
  const { mainPool, rateLimiterPool } = createTestPools();
  
  configuration({
    store: {
      main: mainPool,
      rate_limiters_pool: {
        store: rateLimiterPool,
        dbName: 'myapp'
      }
    },
    telegram: {
      token: 'test-telegram-token'
    },
    password: {
      pepper: 'test-pepper-secret-key'
    },
    magic_links: {
      jwt_secret_key: 'test-magic-links-secret',
      domain: 'https://example.com'
    },
    jwt: {
      jwt_secret_key: 'test-jwt-secret-key',
      access_tokens: {
        expiresIn: '15m'
      },
      refresh_tokens: {
        rotateOnEveryAccessExpiry: true,
        refresh_ttl: 7 * 24 * 60 * 60 * 1000, 
        domain: 'localhost',
        MAX_SESSION_LIFE: 30 * 24 * 60 * 60 * 1000, 
        maxAllowedSessionsPerUser: 5,
        byPassAnomaliesFor: 24 * 60 * 60 * 1000 
      }
    },
    email: {
      resend_key: 'test-resend-key',
      email: 'test@example.com'
    },
    logLevel: 'info'
  });

  return { mainPool, rateLimiterPool };
}

export async function cleanupTestDatabase() {
  const { mainPool } = createTestPools();
  
  try {
    await mainPool.execute('DELETE FROM users WHERE email LIKE "%test%"');
    await mainPool.execute('DELETE FROM visitors WHERE canary_id LIKE "test-canary-%"');
  } catch (error) {
    console.warn('Cleanup warning:', error);
  } 
}

export async function createTestUser(email: string = 'test@example.com'): Promise<number> {
  const { mainPool } = createTestPools();
  
  try {
    const [existingUsers] = await mainPool.execute<mysql2.RowDataPacket[]>(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );

    if (existingUsers.length > 0) {
      return existingUsers[0].id;
    }

    const canaryId = `test-canary-${Date.now()}-${Math.random()}`;
    const [visitorResult] = await mainPool.execute<mysql2.ResultSetHeader>(
      'INSERT INTO visitors (canary_id, ip_address, user_agent) VALUES (?, ?, ?)',
      [canaryId, '127.0.0.1', 'test-user-agent']
    );

    const visitorId = visitorResult.insertId;

    const [userResult] = await mainPool.execute<mysql2.ResultSetHeader>(
      'INSERT INTO users (name, last_name, email, password_hash, visitor_id) VALUES (?, ?, ?, ?, ?)',
      ['John', 'Doe', email, 'test-password-hash', visitorId]
    );

    return userResult.insertId;
  } finally {
  }
  
}

