import crypto from 'crypto'
import { getPool } from "./jwtAuth/config/configuration.js";
import { ResultSetHeader, RowDataPacket } from 'mysql2';
import { getLogger } from './jwtAuth/utils/logger.js';
import { ensureSha256Hex, toDigestHex } from './jwtAuth/utils/hashChecker.js';

interface token {
  id:         number;
  user_id:    number;
  visitor_id: string;
  token: string;
  valid:      boolean       
  expiresAt:  Date;     
  created_at: Date;  
  usage_count: number;  
  session_started_at: Date;  
}

export interface IssuedRefreshToken {
  raw:       string;
  expiresAt: Date;
}

/**
 * @description
 * Generate and hash a fresh refresh token.
 *
 * @function generateRefreshToken
 * @param {number} ttl - Time to live duration of the refresh token (milliseconds).
 * @param {number} userId - The user's unique identifier.
 * @returns {Promise<IssuedRefreshToken>} A promise resolving to an issued token object.
 *
 * @example
 * generateRefreshToken(1000 * 60 * 60 * 24 * 3, 14);
 */
export async function generateRefreshToken(ttl: number, userId: number): Promise<IssuedRefreshToken> {
    const log = getLogger().child({service: 'auth', branch: 'refresh tokens'})
    log.info({userId},'generating a new refresh token...')
    const token = crypto.randomBytes(64).toString('hex');
    const {input: hashedToken} = await toDigestHex(token)
    const expiresAt = new Date(Date.now() + ttl);
    const pool = getPool()
    try { 
    const mainStm = `
    INSERT INTO refresh_tokens
    (user_id, token, valid, expiresAt, session_started_at)
    VALUES (?, ?, ?,  DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND), UTC_TIMESTAMP())
    `;

    const mainParams = [userId, hashedToken, true, Math.floor(ttl / 1000)];
    await pool.execute(mainStm, mainParams); 

    } catch (err) {
        log.error({err},'Error generating refresh token')
        throw new Error('DB error generating refresh token');
    }
    log.info({userId},'success')
  return {
    raw: token,
    expiresAt,
  };
}
/**
 * @description
 * Verify and consume a refresh token. After calling this, the token cannot be used a second time,
 * suitable when refresh tokens rotate on every access token rotation. Additionally, if a revoked or
 * already used token is presented again, it will be deleted and the user will be forced to log in
 * again on all open sessions.
 *
 * @param {string} clientToken - The refresh token to verify and consume.
 *
 * @returns {Promise<{
 *   valid: boolean;
 *   userId?: number;
 *   visitor_id?: number;
 *   reason?: string;
 *   sessionTTL?: Date;
 * }>} Resolves with the validity result and metadata if valid.
 *
 * @example
 * await consumeAndVerifyRefreshToken('clientToken');
 *
 * @see {@link ./refreshTokens.js}
 */
export async function consumeAndVerifyRefreshToken(clientToken: string): 
Promise<
  { valid: boolean; userId?: number; visitor_id?: string;  reason?: string, sessionTTL?: Date}
  > {
const strictAuth = getLogger().child({service: 'auth', branch: 'strict auth'})
strictAuth.info('consumeAndVerifyRefreshToken entered, verifying token...')
const { input: maybeDigest } = await toDigestHex(clientToken);  
const hashedClientToken = ensureSha256Hex(maybeDigest);    
const pool = getPool();

const conn = await pool.getConnection();

try { 
await conn.beginTransaction();  
const [info] = await conn.execute<ResultSetHeader>(
  `UPDATE refresh_tokens
     SET usage_count = usage_count + 1
   WHERE token       = ?
     AND valid       = 1
     AND usage_count = 0
     AND expiresAt > UTC_TIMESTAMP()`,          
  [hashedClientToken]
);

// Means the info satement didnt satisfied. token is NOT valid, token didnt found, or usage count is > 0
if (info.affectedRows === 0) {
    // Find out why
    const [rows] = await conn.execute<RowDataPacket[]>('SELECT valid, user_id, usage_count FROM refresh_tokens WHERE token = ? FOR UPDATE', [hashedClientToken]);

    if (rows.length === 0) {
        await conn.commit();
         strictAuth.warn('A non-existent refresh token was presented.');
        return { valid: false, reason: 'Token not found' };
    }
    const tokenStatus = rows[0];

    if (!tokenStatus.valid) {
        await conn.commit();
        strictAuth.warn({userId: tokenStatus.user_id}, 'A revoked refresh token was used.');
        return { valid: false, reason: 'Token has been revoked' };
    }

 if (tokenStatus.usage_count > 0) {
    strictAuth.warn({userId: tokenStatus.user_id}, 'A second use of a refresh token was detected. Revoking all sessions.');

  const [revokeAllClientsTokens] = await conn.execute<ResultSetHeader>(`
    UPDATE refresh_tokens
        SET valid = 0
        WHERE user_id = ? `
    ,[tokenStatus.user_id]);

    await conn.commit();
    return { valid: false, reason: 'Token already used, Please login again' };
}

  await conn.commit();
  strictAuth.error({userId: tokenStatus.user_id},'Invalid token - unexpected results.')
  return { valid: false, reason: 'Invalid token' };
}
    
        const [rows]  = await conn.execute<RowDataPacket[]>
        (`SELECT 
            refresh_tokens.user_id, 
            refresh_tokens.valid, 
            refresh_tokens.expiresAt,
            refresh_tokens.session_started_at,
            users.visitor_id  
        FROM refresh_tokens 
            JOIN users ON refresh_tokens.user_id = users.id 
        WHERE refresh_tokens.token = ? LIMIT 1`, [hashedClientToken]);
        

        if (!rows || rows.length === 0) {
              strictAuth.info('Token not found')
            await conn.rollback();
        return { 
            valid: false, 
            reason: 'Token not found' 
         };
        }

        const results = rows[0] as token;
        if (!results.valid) {
            const [deleteIvalidToken] = await conn.execute<ResultSetHeader>(`        
                DELETE FROM refresh_tokens
                WHERE token   = ? 
                  AND user_id = ?
                  AND valid   = 0
                  AND user_id IS NOT NULL 
                LIMIT 1`, [hashedClientToken ,results.user_id]);
                strictAuth.warn({userId: results.user_id},'Usage of revoked token detected, token deleted')
            await conn.commit();
            return {
                valid: false,
                reason: "Token has been revoked"
            }
        };

        const expiryTime = results.expiresAt.getTime();
        if (expiryTime < Date.now()) {
            await conn.execute(`
                UPDATE refresh_tokens
                  JOIN users
                     ON users.id = refresh_tokens.user_id
                 SET 
                 refresh_tokens.valid = 0,
                 users.last_mfa_at = NULL
                 WHERE token = ? 
                 AND refresh_tokens.valid = 1 
                 `, [hashedClientToken]);
                 await conn.commit();
            strictAuth.warn({userId: results.user_id},'Token expired, and last_mfa_at set to null')
            return {
                valid: false,
                reason: "Token expired",
                userId: results.user_id
            }
        };

    await conn.commit();
    strictAuth.info({userId: results.user_id},'Token verified and consumed successfully')
    return {
        valid: true,
        userId: results.user_id,
        visitor_id: results.visitor_id,
        sessionTTL: results.session_started_at
    }
    
} catch(err) {
    await conn.rollback();
    strictAuth.error({err},'Error verifying the refresh token')
    throw new Error('DB error verifying refresh token');
}  finally {
    conn.release();
  }
}


/**
 * @description
 * Verify a refresh token, revoke it on expiry, and detect if a revoked token is being reused.
 *
 * @param {string} clientToken - The refresh token to verify.
 *
 * @returns {Promise<{ valid: boolean; userId?: number; visitor_id?: number; reason?: string; sessionStartedAt?: Date; expiresAt?:Date }>}
 * Resolves with an object describing token validity and additional metadata if valid.
 *
 * @example
 * await verifyRefreshToken('clientToken');
 */
export async function verifyRefreshToken(clientToken: string): 
Promise<
  { valid: boolean; userId?: number; visitor_id?: string;  reason?: string, sessionStartedAt?:Date, expiresAt?:Date }
  > {
    const log = getLogger().child({service: 'auth', branch: 'refresh tokens'})

log.info('verifyRefreshToken entered, verifying token...')

const { input: maybeDigest } = await toDigestHex(clientToken);  
const hashedClientToken = ensureSha256Hex(maybeDigest);    

const pool = getPool()
const conn = await pool.getConnection();

    try { 
        await conn.beginTransaction();

        const [rows]  = await conn.execute<RowDataPacket[]>
        (`SELECT 
        refresh_tokens.user_id, 
        refresh_tokens.valid, 
        refresh_tokens.expiresAt,
        refresh_tokens.session_started_at,
        users.visitor_id  
        FROM refresh_tokens 
            JOIN users ON refresh_tokens.user_id = users.id 
        WHERE refresh_tokens.token = ? LIMIT 1
        FOR UPDATE
        `, [hashedClientToken]);

        if (!rows || rows.length === 0) {
            log.info('Token not found')
            await conn.rollback()
        return { 
            valid: false, 
            reason: 'Token not found' 
         };
        }

        const results = rows[0] as token;
        if (!results.valid) {
          const [deleteIvalidToken] = await conn.execute<ResultSetHeader>(`        
                DELETE FROM refresh_tokens
                WHERE token   = ? 
                  AND user_id = ?
                  AND valid   = 0
                  AND user_id IS NOT NULL 
                LIMIT 1`, [hashedClientToken, results.user_id]);
                log.warn({userId: results.user_id},'Usage of revoked token detected, token deleted')
               await conn.commit()
            return {
                valid: false,
                reason: "Token has been revoked"
            }
        };

        const expiryTime = results.expiresAt.getTime();
        if (expiryTime < Date.now()) {
            await conn.execute(`
                UPDATE refresh_tokens
                  JOIN users
                     ON users.id = refresh_tokens.user_id
                 SET 
                 refresh_tokens.valid = 0,
                 users.last_mfa_at = NULL
                 WHERE token = ? 
                 AND refresh_tokens.valid = 1 
                 `, [hashedClientToken]);
            log.warn({userId: results.user_id},'Token expired, and last_mfa_at set to null')
            await conn.commit()
            return {
                valid: false,
                reason: "Token expired",
                userId: results.user_id
            }
        };

        const [upd] = await conn.execute<ResultSetHeader>(
        `UPDATE refresh_tokens
            SET usage_count = usage_count + 1
            WHERE token = ?
            AND valid = 1
            AND expiresAt > UTC_TIMESTAMP()`,
        [hashedClientToken]
        );

        if (upd.affectedRows !== 1) {
              log.warn(
                { userId: results.user_id, affectedRows: upd.affectedRows },
                'Token validation passed but UPDATE failed - possible clock skew or race condition'
            );
            await conn.rollback();
            return { valid: false, reason: 'Invalid or expired', userId: results.user_id };
        }

     await conn.commit();
    log.info({userId: results.user_id},'Verified token successfully')
    return {
        valid: true,
        userId: results.user_id,
        visitor_id: results.visitor_id,
        sessionStartedAt: results.session_started_at,
        expiresAt: results.expiresAt
    }
    
} catch(err) {
    await conn.rollback()
    log.error({err},'Error verifying the refresh token')
    throw new Error('DB error verifying refresh token');
} finally {
    conn.release();
}
}

/**
 * @description
 * Revoke any valid client token. 
 *
 * @function revokeRefreshToken
 * @param {string} clientToken - The token to revoke.
 *
 * @returns {Promise<{success: boolean}>} An object indicating whether revocation succeeded.
 *
 * @example
 * revokeRefreshToken('clientToken');
 */
export async function revokeRefreshToken(clientToken: string): Promise<{success: boolean}> {
    const log = getLogger().child({service: 'auth', branch: 'refresh tokens'})
    log.info('revokeRefreshToken entered. revoking token...')
    const { input: maybeDigest } = await toDigestHex(clientToken);  
    const hashedClientToken = ensureSha256Hex(maybeDigest);    

    const pool = getPool()
   try { 
        await pool.execute<RowDataPacket[]>
        ("UPDATE refresh_tokens SET valid = 0 WHERE token = ? LIMIT 1", [hashedClientToken]);

        } catch(err) {
            log.error({err}, 'Error revoking a refresh token')
            return {success: false}
        }
          log.info('revoked Refresh.')
        return {success: true}
}

/**
 * @description
 * Revoke *ALL* user current valid refresh tokens. 
 *
 * @function revokeRefreshToken
 * @param {string} userId - The id of the user.
 *
 * @returns {Promise<{success: boolean}>} An object indicating whether revocation succeeded.
 *
 * @example
 * revokeRefreshToken('clientToken');
 */
export async function revokeAllRefreshTokens(userId: string | number): Promise<{success: boolean}> {
    const log = getLogger().child({service: 'auth', branch: 'refresh tokens'})
    log.info('revokeAllRefreshTokens entered. revoking ALL user tokens...')

    const pool = getPool()
   try { 
    
        await pool.execute<RowDataPacket[]>
        (`
          UPDATE refresh_tokens
            SET valid = 0
            WHERE user_id = ?
              AND valid = 1
              AND user_id IS NOT NULL
          `, [userId]
        );

        } catch(err) {
            log.error({err}, 'Error revoking a refresh tokens')
            return {success: false}
        }
          log.info('revoked all refresh tokens.')
        return {success: true}
}