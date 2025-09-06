// Setup script for comprehensive testing
import mysql from 'mysql2/promise';
import mysql2 from 'mysql2';
import { configuration } from '../dist/jwtAuth/config/configuration.js';

// Create database connections for testing
const promisePool = mysql.createPool({
  host: '127.0.0.1',
  port: 3306,
  user: 'root',
  password: '1234',
  database: 'app_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

const callbackPool = mysql2.createPool({
  host: '127.0.0.1',
  port: 3306,
  user: 'root',
  password: '1234',
  database: 'app_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Configure the library for testing
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
    pepper: 'test-pepper-for-comprehensive-testing'
  },
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
      refresh_ttl: 24 * 60 * 60 * 1000, // 24 hours
      domain: 'test.example.com',
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

async function tablesForBotDetectorAndAnomalies(connection) {
    const createVisitorsTable = `
        CREATE TABLE IF NOT EXISTS visitors (
            visitor_id INT AUTO_INCREMENT UNIQUE NOT NULL,
            canary_id VARCHAR(64) PRIMARY KEY,
            ip_address VARCHAR(45),
            user_agent TEXT,
            country VARCHAR(64),
            region VARCHAR(64),
            region_name VARCHAR(350),
            city VARCHAR(64),
            district VARCHAR(260),
            lat VARCHAR(150),
            lon VARCHAR(150),
            timezone VARCHAR(64),
            currency VARCHAR(64),
            isp VARCHAR(64),
            org VARCHAR(64),
            as_org VARCHAR(64),
            device_type VARCHAR(64),
            browser VARCHAR(64),
            proxy BOOLEAN,
            proxy_allowed BOOLEAN DEFAULT true,
            hosting BOOLEAN,
            hosting_allowed BOOLEAN DEFAULT true,
            is_bot BOOLEAN DEFAULT false,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            request_count INT DEFAULT 1,
            deviceVendor VARCHAR(64) DEFAULT 'unknown',
            deviceModel VARCHAR(64) DEFAULT 'unknown',
            browserType VARCHAR(64) DEFAULT 'unknown',
            browserVersion VARCHAR(64) DEFAULT 'unknown',
            os VARCHAR(64) DEFAULT 'unknown',
            suspicos_activity_score INT DEFAULT 0
        );
        `;

const userAgentMetadataSQL = `
    CREATE TABLE IF NOT EXISTS user_agent_metadata (
      http_user_agent varchar(255) NOT NULL,
      metadata_description text,
      metadata_tool varchar(255) DEFAULT NULL,
      metadata_category varchar(255) DEFAULT NULL,
      metadata_link text,
      metadata_priority varchar(1000) DEFAULT NULL,
      metadata_fp_risk varchar(50) DEFAULT NULL,
      metadata_severity varchar(50) DEFAULT NULL,
      metadata_usage varchar(255) DEFAULT NULL,
      metadata_flow_from_external varchar(1000) DEFAULT NULL,
      metadata_flow_from_internal varchar(1000) DEFAULT NULL,
      metadata_flow_to_internal varchar(1000) DEFAULT NULL,
      metadata_flow_to_external varchar(1000) DEFAULT NULL,
      metadata_for_successful_external_login_events varchar(1000) DEFAULT NULL,
      metadata_comment text,
      PRIMARY KEY (http_user_agent)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
    `;
    
    const createBannedTable = `
        CREATE TABLE IF NOT EXISTS banned (
            canary_id VARCHAR(64) PRIMARY KEY,
            ip_address VARCHAR(45),
            country VARCHAR(64),
            user_agent TEXT,
            reason TEXT,
            score INT DEFAULT NULL,
            FOREIGN KEY (canary_id) REFERENCES visitors(canary_id) 
        );
    `;

    try {
        await connection.execute(createVisitorsTable);
        await connection.execute(createBannedTable);
        await connection.execute(userAgentMetadataSQL);
        // Skip loading CSV data for now as it requires local file access
        console.log('Bot detector tables created successfully.');
    } catch (error) {
        console.error('Error creating bot detector tables:', error);
        throw error;
    }
}

async function tablesForAuth(connection) {
    const createUsersTable = `
        CREATE TABLE IF NOT EXISTS users (
          id              int AUTO_INCREMENT PRIMARY KEY,
          last_mfa_at     DATETIME NULL,
          active_user     BOOLEAN DEFAULT 1,
          name            VARCHAR(100) NOT NULL,
          last_name       VARCHAR(100) NOT NULL,
          email           VARCHAR(255) UNIQUE NOT NULL,
          avatar          VARCHAR(200),
          password_hash   VARCHAR(255) NOT NULL,
          provider        VARCHAR(50),   
          provider_id     VARCHAR(100),
          created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
          updated_at      TIMESTAMP NOT NULL DEFAULT NOW(),
          remember_user   BOOLEAN DEFAULT 0,
          terms_and_privacy_agreement   BOOLEAN DEFAULT 0,
          accepts_marketing BOOLEAN DEFAULT 0,
          country         VARCHAR(100),
          city            VARCHAR(100),
          address         VARCHAR(200),
          zip             VARCHAR(100),
          district        VARCHAR(100),
          visitor_id      int   NOT NULL,
          CONSTRAINT fk_identified_visitor
            FOREIGN KEY (visitor_id) 
            REFERENCES visitors(visitor_id)
            ON UPDATE CASCADE 
            ON DELETE RESTRICT
        );
        `;

    const createAuthTable = `
        CREATE TABLE IF NOT EXISTS refresh_tokens (
          id              int AUTO_INCREMENT PRIMARY KEY,
          user_id         INT NOT NULL,
          token          VARCHAR(600) NOT NULL UNIQUE,
          valid          BOOLEAN DEFAULT 0,
         created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
         expiresAt       TIMESTAMP NOT NULL,
         usage_count     INT DEFAULT 0,
         session_started_at TIMESTAMP,

          CONSTRAINT users_tokens
            FOREIGN KEY(user_id) 
            REFERENCES users(id)
            ON DELETE  CASCADE
        );
  `;

     const createMFATable = `
        CREATE TABLE mfa_codes (
          id          INT AUTO_INCREMENT PRIMARY KEY,
          user_id     INT NOT NULL UNIQUE,
          token       VARCHAR(600) NOT NULL UNIQUE,
          jti         VARCHAR(500) NOT NULL UNIQUE,
          code_hash   CHAR(64) NOT NULL UNIQUE,
          expires_at  DATETIME NOT NULL,
          used        BOOLEAN DEFAULT 0,
          created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
          INDEX(user_id), INDEX(code_hash), INDEX(token), INDEX(used),
          
          CONSTRAINT users_mfa
            FOREIGN KEY(user_id) 
            REFERENCES users(id)
            ON DELETE  CASCADE,

          CONSTRAINT token_mfa
            FOREIGN KEY(token) 
            REFERENCES refresh_tokens(token)
            ON DELETE  CASCADE 
        );
  `;

      try {
        await connection.execute(createUsersTable);
        await connection.execute(createAuthTable);
        await connection.execute(createMFATable);
        console.log('Auth tables created successfully.');
    } catch (error) {
        console.error('Error creating auth tables:', error);
        throw error;
    }
}

try {
  console.log('Setting up database tables...');
  await tablesForBotDetectorAndAnomalies(promisePool);
  await tablesForAuth(promisePool);
  console.log('Database setup complete!');
} catch (error) {
  console.error('Error setting up database:', error);
  process.exit(1);
} finally {
  await promisePool.end();
  callbackPool.end();
}