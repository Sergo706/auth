import { Pool } from 'mysql2/promise';
import { getPool } from '../config/configuration.js';

async function tablesForAuth (connection: Pool): Promise<void> {
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
          created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          remember_user   BOOLEAN DEFAULT 0,
          terms_and_privacy_agreement   BOOLEAN DEFAULT 0,
          accepts_marketing BOOLEAN DEFAULT 0,
          country         VARCHAR(100),
          city            VARCHAR(100),
          address         VARCHAR(200),
          zip             VARCHAR(100),
          district        VARCHAR(100),
          visitor_id      CHAR(36) NOT NULL,
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
         created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
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
        CREATE TABLE IF NOT EXISTS mfa_codes (
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
        console.log('Tables created successfully.');
    } catch (error) {
        console.error('Error creating tables:', error);
        throw error;
    }
}

export async function makeTables() {
    const store = getPool()
    await tablesForAuth(store)
}