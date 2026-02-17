import mysql from 'mysql2';
import mysql2 from 'mysql2/promise';
import { configuration } from '../../src/jwtAuth/config/configuration.js';
import { config } from 'dotenv';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


config({ path: path.resolve(__dirname, '../../.env.test') });

const TEST_DB_CONFIG = {
  host: process.env.TEST_DB_HOST || 'localhost',
  port: Number(process.env.TEST_DB_PORT) || 3306,
  user: process.env.TEST_DB_USER,
  password: process.env.TEST_DB_PASSWORD,
  database: process.env.TEST_DB_NAME || 'my_auth_tests_db',
  multipleStatements: true
};


let pools: { mainPool: mysql2.Pool; rateLimiterPool: mysql.Pool } | null = null;

export function createTestPools() {
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
        dbName: 'my_auth_tests_db'
      }
    },
    telegram: {
      token: 'test-telegram-token'
    },
    password: {
      pepper: 'test-pepper-secret-key'
    },
    magic_links: {
      jwt_secret_key: 'super_long_secret',
      domain: 'http://localhost:10000'
    },
    jwt: {
      jwt_secret_key: 'super_long_secret',
      access_tokens: {
        expiresIn: '15m'
      },
      refresh_tokens: {
        rotateOnEveryAccessExpiry: false,
        refresh_ttl: 259200000, 
        domain: 'localhost',
        MAX_SESSION_LIFE: 30 * 24 * 60 * 60 * 1000, 
        maxAllowedSessionsPerUser: 5,
        byPassAnomaliesFor: 24 * 60 * 60 * 1000 
      }
    },
    email: {
      resend_key: 're_FKjU5k87_A3xQS9wtERAcLiu6wFdQpuUk',
      email: 'noreply@riavzon.com'
    },
    logLevel: 'info',
    trustUserDeviceOnAuth: false,
    botDetector: {
        enableBotDetector: false
    },
    htmlSanitizer: {
        IrritationCount: 50,
        maxAllowedInputLength: 50000
    }
  });

  return { mainPool, rateLimiterPool };
}

export async function cleanupTestDatabase(): Promise<void> {
  const { mainPool } = createTestPools();
  
  try {
    // Delete in order respecting foreign key constraints (children first)
    await mainPool.execute('DELETE FROM refresh_tokens WHERE user_id IN (SELECT id FROM users WHERE email LIKE "%test%")');
    await mainPool.execute('DELETE FROM mfa_codes WHERE user_id IN (SELECT id FROM users WHERE email LIKE "%test%")');
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

