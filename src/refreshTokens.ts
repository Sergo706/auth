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
 const log = getLogger().child({service: 'auth', branch: 'refresh tokens'})
 const strictAuth = getLogger().child({service: 'auth', branch: 'strict auth'})

export async function rotateRefreshToken(ttl: number, userId: number, oldClientToken: string, hashed?: boolean): Promise<{
    rotated: boolean,
    raw?: string;
    hashedToken?: string;
    expiresAt?: Date;
}> {
const pool = await getPool()   
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

export async function generateRefreshToken(ttl: number, userId: number): Promise<IssuedRefreshToken> {
    log.info({userId},'generating a new refresh token...')
    const token = crypto.randomBytes(64).toString('hex');
    const hashedToken = createHash('sha256').update(token).digest('hex');
    const expiresAt = new Date(Date.now() + ttl);
    const pool = await getPool()
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

export async function consumeAndVerifyRefreshToken(clientToken: string, hashed?: boolean): 
Promise<
  { valid: boolean; userId?: number; visitor_id?: number;  reason?: string, sessionTTL?: Date}
  > {
strictAuth.info('consumeAndVerifyRefreshToken entered, verifying token...')
let hashedClientToken = clientToken;

if (!hashed) {
    hashedClientToken = createHash('sha256').update(clientToken).digest('hex');
}
const pool = await getPool();

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



export async function verifyRefreshToken(clientToken: string, hashed?: boolean): 
Promise<
  { valid: boolean; userId?: number; visitor_id?: number;  reason?: string, sessionTTL?:Date }
  > {
let hashedClientToken = clientToken;
log.info('verifyRefreshToken entered, verifing token...')
if (!hashed) {
    hashedClientToken = createHash('sha256').update(clientToken).digest('hex');
}
const pool = await getPool()
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



export async function revokeRefreshToken(clientToken: string, hashed?: boolean): Promise<{success: boolean}> {
    let hashedClientToken = clientToken; 
    log.info('revokeRefreshToken entered. revoking token...')
    if (!hashed) {
        hashedClientToken = createHash('sha256').update(clientToken).digest('hex');
    }
    const pool = await getPool()
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


