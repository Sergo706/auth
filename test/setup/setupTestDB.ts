import mysql2 from 'mysql2/promise';
import 'dotenv/config';

const DB_CONFIG = {
  host: process.env.DB_HOST!,
  port: Number(process.env.DB_PORT!),
  user: process.env.DB_USER!,
  password: process.env.DB_PASS!,
  database: process.env.DB_NAME!,
  multipleStatements: true
};

async function createTablesForTesting() {
  const connection = await mysql2.createConnection(DB_CONFIG);
  
  try {
    console.log('Creating test database tables...');

    await connection.execute(`
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
        hosting BOOLEAN,
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
      )
    `);

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        visitor_id INT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        email_verified BOOLEAN DEFAULT FALSE,
        last_mfa_at TIMESTAMP NULL,
        FOREIGN KEY (visitor_id) REFERENCES visitors(visitor_id)
      )
    `);

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        token VARCHAR(64) UNIQUE NOT NULL,
        valid BOOLEAN DEFAULT TRUE,
        expiresAt DATETIME NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        usage_count INT DEFAULT 0,
        session_started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS banned (
        canary_id VARCHAR(64) PRIMARY KEY,
        ip_address VARCHAR(45),
        country VARCHAR(64),
        user_agent TEXT,
        reason TEXT,
        score INT DEFAULT NULL,
        FOREIGN KEY (canary_id) REFERENCES visitors(canary_id)
      )
    `);

    console.log('Test database tables created successfully!');
  } catch (error) {
    console.error('Error creating tables:', error);
    throw error;
  } finally {
    await connection.end();
  }
}

createTablesForTesting()
  .then(() => {
    console.log('Database setup complete');
    process.exit(0);
  })
  .catch((error) => {
    console.error('Database setup failed:', error);
    process.exit(1);
  });