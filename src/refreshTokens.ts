import crypto, { createHash } from 'crypto'
import { getPool } from "./jwtAuth/config/dbConnection.js";
import { ResultSetHeader, RowDataPacket } from 'mysql2';
import { getLogger } from './jwtAuth/utils/logger.js';

interface token {
  id:         number;
  user_id:    number;
  visitor_id: number;
  token: string;
  valid:      boolean       
  expiresAt:  Date;     
  created_at: Date;  
  usage_count: number;  
  session_started_at: Date;  
}

export interface IssuedRefreshToken {
  raw:       string;
  hashedToken: string;
  expiresAt: Date;
}



/**
 * @description
 * Search for and rotate the provided refresh token.
 *
 * @function rotateRefreshToken
 * @param {number} ttl - Time-to-live duration (in milliseconds).
 * @param {number} userId - The user's unique identifier.
 * @param {string} oldClientToken - The current refresh token to be rotated.
 * @param {boolean} [hashed] - If true, indicates the provided token is already hashed.
 *
 * @returns {Promise<object>} Resolves to an object containing:
 * - `rotated` {boolean}: Whether rotation was successful.
 * - `raw?` {string}: The new raw token string, if rotation succeeded.
 * - `hashedToken?` {string}: Hashed value of the new token, if rotation succeeded.
 * - `expiresAt?` {Date}: Expiration date of the new token, if rotation succeeded.
 * 
 * @example
 * rotateRefreshToken(1000 * 60 * 60 * 24 * 3, 14, oldToken, true);
 */
export async function rotateRefreshToken(ttl: number, userId: number, oldClientToken: string, hashed?: boolean): Promise<{
    rotated: boolean,
    raw?: string;
    hashedToken?: string;
    expiresAt?: Date;
}> {
const log = getLogger().child({service: 'auth', branch: 'refresh tokens'})
const pool = getPool()  
log.info({userId},'generating and rotating new refresh tokens...')
    const token = crypto.randomBytes(64).toString('hex');
    const hashedToken = createHash('sha256').update(token).digest('hex');
    const expiresAt = new Date(Date.now() + ttl);
    let oldHashedClientToken = oldClientToken;  

    if (!hashed) {
            oldHashedClientToken = createHash('sha256').update(oldClientToken).digest('hex');
    }

    try {
        const [rotate] = await pool.execute<ResultSetHeader>(`
            UPDATE refresh_tokens
             SET 
              token = ?,
              expiresAt = ?,
              valid = 1
            WHERE 
              token = ?
              AND user_id = ?
            `,[hashedToken, expiresAt, oldHashedClientToken, userId]); 
           
        if (rotate.affectedRows !== 1) {
            log.warn({userId},'Token not rotated, old token is not found');
             return {
                rotated: false
            }
        } 

    } catch(err) {
         log.error({userId, err},'error rotating refresh token');
         throw new Error('DB error rotating refresh token');
    }
     log.info({userId},'Rotated refresh token')
 return {
     rotated: true,
     raw: token,
     hashedToken: hashedToken,
     expiresAt: expiresAt
 }

}
/**
 * @description
 * Generate and hash a fresh refresh token.
 *
 * @function generateRefreshToken
 * @param {number} ttl - Time-to-live duration of the refresh token (milliseconds).
 * @param {number} userId - The user's unique identifier.
 * @returns {Promise<IssuedRefreshToken>} A promise resolving to an issued and hashed refresh token object.
 *
 * @example
 * generateRefreshToken(1000 * 60 * 60 * 24 * 3, 14);
 */
export async function generateRefreshToken(ttl: number, userId: number): Promise<IssuedRefreshToken> {
    const log = getLogger().child({service: 'auth', branch: 'refresh tokens'})
    log.info({userId},'generating a new refresh token...')
    const token = crypto.randomBytes(64).toString('hex');
    const hashedToken = createHash('sha256').update(token).digest('hex');
    const expiresAt = new Date(Date.now() + ttl);
    const pool = getPool()
    try { 
    const mainStm = `
    INSERT INTO refresh_tokens
    (user_id, token, valid, expiresAt, session_started_at)
    VALUES (?, ?, ?, ?, NOW())
    `;

    const mainParams = [userId, hashedToken, true, expiresAt];
    await pool.execute(mainStm, mainParams); 

    } catch (err) {
        log.error({err},'Error generating refresh token')
        console.warn(`Error generating refresh token: ${err}`);
        throw new Error('DB error generating refresh token');
    }
    log.info({userId},'success')
  return {
    raw: token,
    hashedToken: hashedToken,
    expiresAt,
  };
}
/**
 * @description
 * Verify and consume a refresh token. After calling this, the token cannot be used a second time—
 * suitable when refresh tokens rotate on every access token rotation. Additionally, if a revoked or
 * already-used token is presented again, it will be deleted and the user will be forced to log in
 * again on all open sessions. If the token is hashed, set the `hashed` parameter to true.
 *
 * @param {string} clientToken - The refresh token to verify and consume.
 * @param {boolean} [hashed] - If true, indicates `clientToken` is already hashed.
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
 * await consumeAndVerifyRefreshToken('clientToken', true);
 *
 * @see {@link ./refreshTokens.js}
 */
export async function consumeAndVerifyRefreshToken(clientToken: string, hashed?: boolean): 
Promise<
  { valid: boolean; userId?: number; visitor_id?: number;  reason?: string, sessionTTL?: Date}
  > {
const strictAuth = getLogger().child({service: 'auth', branch: 'strict auth'})
strictAuth.info('consumeAndVerifyRefreshToken entered, verifying token...')
let hashedClientToken = clientToken;

if (!hashed) {
    hashedClientToken = createHash('sha256').update(clientToken).digest('hex');
}
const pool = getPool();

const conn   = await pool.getConnection();

try { 
await conn.beginTransaction();  
const [info] = await conn.execute<ResultSetHeader>(
  `UPDATE refresh_tokens
     SET usage_count = usage_count + 1
   WHERE token       = ?
     AND valid       = 1
     AND usage_count = 0`,          
  [hashedClientToken]
);
// Means the info satement didnt satisfied. token is NOT valid, token didnt found, and usage count is > 0
if (info.affectedRows === 0) {
  const [revokeAllClientsTokens] = await conn.execute<ResultSetHeader>(`
    UPDATE refresh_tokens
        SET valid = 0
    WHERE user_id = (
        SELECT user_id FROM refresh_tokens
        WHERE token = ?
        LIMIT 1
    )
    AND user_id IS NOT NULL`
    ,[hashedClientToken]);

  await conn.commit();
  strictAuth.info('Token already been used, aborted')
  return { valid: false, reason: 'Token already used, Please login again' };
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
            const [deleteIvalidToken] = await pool.execute<ResultSetHeader>(`        
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
    strictAuth.error({err},'Error verifing the refresh token')
    throw new Error('DB error verifying refresh token');
}  finally {
    conn.release();
  }
}


/**
 * @description
 * Verify a refresh token, revoke it on expiry, and detect if a revoked token is being reused.  
 * If the token is hashed, set the `hashed` parameter to true.
 *
 * @param {string} clientToken - The refresh token to verify.
 * @param {boolean} [hashed] - If true, indicates `clientToken` is already hashed.
 *
 * @returns {Promise<{ valid: boolean; userId?: number; visitor_id?: number; reason?: string; sessionTTL?: Date }>}
 * Resolves with an object describing token validity and additional metadata if valid.
 *
 * @example
 * await verifyRefreshToken('clientToken', true);
 */
export async function verifyRefreshToken(clientToken: string, hashed?: boolean): 
Promise<
  { valid: boolean; userId?: number; visitor_id?: number;  reason?: string, sessionTTL?:Date }
  > {
    const log = getLogger().child({service: 'auth', branch: 'refresh tokens'})
let hashedClientToken = clientToken;
log.info('verifyRefreshToken entered, verifing token...')
if (!hashed) {
    hashedClientToken = createHash('sha256').update(clientToken).digest('hex');
}
const pool = getPool()
    try { 
        const [info] = await pool.execute<ResultSetHeader>(
           `UPDATE refresh_tokens
                SET usage_count = usage_count + 1
            WHERE token       = ?
                AND valid       = 1`,          
            [hashedClientToken]
        );
        const [rows]  = await pool.execute<RowDataPacket[]>
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
            log.info('Token not found')
        return { 
            valid: false, 
            reason: 'Token not found' 
         };
        }

        const results = rows[0] as token;
        if (!results.valid) {
          const [deleteIvalidToken] = await pool.execute<ResultSetHeader>(`        
                DELETE FROM refresh_tokens
                WHERE token   = ? 
                  AND user_id = ?
                  AND valid   = 0
                  AND user_id IS NOT NULL 
                LIMIT 1`, [hashedClientToken, results.user_id]);
                log.warn({userId: results.user_id},'Usage of revoked token detcted, token deleted')
            return {
                valid: false,
                reason: "Token has been revoked"
            }
        };

        const expiryTime = results.expiresAt.getTime();
        if (expiryTime < Date.now()) {
            await pool.execute(`
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
            return {
                valid: false,
                reason: "Token expired",
                userId: results.user_id
            }
        };
        
    log.info({userId: results.user_id},'Verified token succesfuly')
    return {
        valid: true,
        userId: results.user_id,
        visitor_id: results.visitor_id,
        sessionTTL: results.session_started_at
    }
    
} catch(err) {
    log.error({err},'Error verifing the refresh token')
    throw new Error('DB error verifying refresh token');
}
}

/**
 * @description
 * Revoke any valid client token. If the token is hashed, set the hashed parameter as true.
 *
 * @function revokeRefreshToken
 * @param {string} clientToken - The token to revoke.
 * @param {boolean} [hashed] - Indicates if the provided token is already hashed.
 *
 * @returns {Promise<{success: boolean}>} An object indicating whether revocation succeeded.
 *
 * @example
 * revokeRefreshToken('clientToken', true);
 */
export async function revokeRefreshToken(clientToken: string, hashed?: boolean): Promise<{success: boolean}> {
    const log = getLogger().child({service: 'auth', branch: 'refresh tokens'})
    let hashedClientToken = clientToken; 
    log.info('revokeRefreshToken entered. revoking token...')
    if (!hashed) {
        hashedClientToken = createHash('sha256').update(clientToken).digest('hex');
    }
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


