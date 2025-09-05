import mysql from 'mysql2';
import mysql2 from 'mysql2/promise';
import { configuration } from '../src/jwtAuth/config/configuration.js';

// Test database configuration
const TEST_DB_CONFIG = {
  host: '127.0.0.1',
  port: 3306,
  user: 'root',
  password: '1234',
  database: 'app_db',
  // Enable local file loading for CSV import
  local_infile: true,
  multipleStatements: true
};

// Create connection pools for testing
export function createTestPools() {
  // Promise-based pool for main operations
  const mainPool = mysql2.createPool({
    ...TEST_DB_CONFIG,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });

  // Callback-based pool for rate limiters
  const rateLimiterPool = mysql.createPool({
    ...TEST_DB_CONFIG,
    waitForConnections: true,
    connectionLimit: 5,
    queueLimit: 0
  });

  return { mainPool, rateLimiterPool };
}

// Minimal test configuration
export function setupTestConfiguration() {
  const { mainPool, rateLimiterPool } = createTestPools();
  
  configuration({
    store: {
      main: mainPool,
      rate_limiters_pool: {
        store: rateLimiterPool,
        dbName: 'app_db'
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
        refresh_ttl: 7 * 24 * 60 * 60 * 1000, // 7 days
        domain: 'localhost',
        MAX_SESSION_LIFE: 30 * 24 * 60 * 60 * 1000, // 30 days
        maxAllowedSessionsPerUser: 5,
        byPassAnomaliesFor: 24 * 60 * 60 * 1000 // 24 hours
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

// Cleanup function for tests
export async function cleanupTestDatabase() {
  const { mainPool } = createTestPools();
  
  try {
    // Clean up test data in the correct order to handle foreign key constraints
    await mainPool.execute('DELETE FROM refresh_tokens WHERE 1=1');
    await mainPool.execute('DELETE FROM users WHERE email LIKE "%test%"');
    await mainPool.execute('DELETE FROM visitors WHERE canary_id LIKE "test-canary-%"');
  } catch (error) {
    console.warn('Cleanup warning:', error);
  } finally {
    await mainPool.end();
  }
}

// Test user creation helper
export async function createTestUser(email: string = 'test@example.com'): Promise<number> {
  const { mainPool } = createTestPools();
  
  try {
    // Check if user already exists
    const [existingUsers] = await mainPool.execute<mysql2.RowDataPacket[]>(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );

    if (existingUsers.length > 0) {
      return existingUsers[0].id;
    }

    // First, create a visitor record
    const canaryId = `test-canary-${Date.now()}-${Math.random()}`;
    const [visitorResult] = await mainPool.execute<mysql2.ResultSetHeader>(
      'INSERT INTO visitors (canary_id, ip_address, user_agent) VALUES (?, ?, ?)',
      [canaryId, '127.0.0.1', 'test-user-agent']
    );

    const visitorId = visitorResult.insertId;

    // Then create a user
    const [userResult] = await mainPool.execute<mysql2.ResultSetHeader>(
      'INSERT INTO users (email, password_hash, visitor_id) VALUES (?, ?, ?)',
      [email, 'test-password-hash', visitorId]
    );

    return userResult.insertId;
  } finally {
    await mainPool.end();
  }
}