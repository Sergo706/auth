import crypto, { createHash } from 'crypto'
import { pool } from "../../config/dbConnection.js";
import { ResultSetHeader, RowDataPacket } from 'mysql2';


interface token {
  id:         number;
  user_id:    number;
  visitor_id: number;
  token: string;
  valid:      boolean       
  expiresAt:  Date;     
  created_at: Date;  
  usage_count: number;    
}

export interface IssuedRefreshToken {
  raw:       string;
  hashedToken: string;
  expiresAt: Date;
}

export async function generateRefreshToken(ttl: number, userId: number): Promise<IssuedRefreshToken> {

    const token = crypto.randomBytes(64).toString('hex');
    const hashedToken = createHash('sha256').update(token).digest('hex');
    const expiresAt = new Date(Date.now() + ttl);

    try { 
    const mainStm = `
    INSERT INTO refresh_tokens
    (user_id, token, valid, expiresAt)
    VALUES (?, ?, ?, ?)
    `;

    const mainParams = [userId, hashedToken, true, expiresAt];
    await pool.execute(mainStm, mainParams); 

    } catch (err) {
        console.warn(`Error generating refresh token: ${err}`);
        throw new Error('DB error generating refresh token');
    }

  return {
    raw: token,
    hashedToken: hashedToken,
    expiresAt,
  };
}

export async function consumeAndVerifyRefreshToken(clientToken: string): 
Promise<
  { valid: boolean; userId?: number; visitor_id?: number;  reason?: string }
  > {

const hashedClientToken = createHash('sha256').update(clientToken).digest('hex');
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
// Means the info satement didnt satisfied. token is NOT valid, token didnt founded, and usage count is > 0
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
  return { valid: false, reason: 'Token already used, Please login again' };
}
    
        const [rows]  = await conn.execute<RowDataPacket[]>
        (`SELECT 
            refresh_tokens.user_id, 
            refresh_tokens.valid, 
            refresh_tokens.expiresAt,
            users.visitor_id  
        FROM refresh_tokens 
            JOIN users ON refresh_tokens.user_id = users.id 
        WHERE refresh_tokens.token = ? LIMIT 1`, [hashedClientToken]);
        

        if (!rows || rows.length === 0) {
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
            await conn.commit();
            return {
                valid: false,
                reason: "Token has been revoked"
            }
        };

        const expiryTime = results.expiresAt.getTime();
        if (expiryTime < Date.now()) {
            await conn.execute(`UPDATE refresh_tokens SET valid = 0 WHERE token = ? LIMIT 1`, [hashedClientToken]);
            await conn.commit();
            return {
                valid: false,
                reason: "Token expired",
                userId: results.user_id
            }
        };
    await conn.commit();
    return {
        valid: true,
        userId: results.user_id,
        visitor_id: results.visitor_id
    }
    
} catch(err) {
    await conn.rollback();
    console.warn(`Error verifing the refresh token, error: ${err}`);
    throw new Error('DB error verifying refresh token');
}  finally {
    conn.release();
  }
}



export async function verifyRefreshToken(clientToken: string): 
Promise<
  { valid: boolean; userId?: number; visitor_id?: number;  reason?: string }
  > {

const hashedClientToken = createHash('sha256').update(clientToken).digest('hex');

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
        users.visitor_id  
        FROM refresh_tokens 
            JOIN users ON refresh_tokens.user_id = users.id 
        WHERE refresh_tokens.token = ? LIMIT 1`, [hashedClientToken]);

        if (!rows || rows.length === 0) {
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
            await pool.execute<ResultSetHeader>(``)
            return {
                valid: false,
                reason: "Token has been revoked"
            }
        };

        const expiryTime = results.expiresAt.getTime();
        if (expiryTime < Date.now()) {
            await pool.execute(`UPDATE refresh_tokens SET valid = 0 WHERE token = ? LIMIT 1`, [hashedClientToken]);
            return {
                valid: false,
                reason: "Token expired",
                userId: results.user_id
            }
        };

    return {
        valid: true,
        userId: results.user_id,
        visitor_id: results.visitor_id
    }
    
} catch(err) {
    console.warn(`Error verifing the refresh token, error: ${err}`);
    throw new Error('DB error verifying refresh token');
}
}



export async function revokeRefreshToken(clientToken: string): Promise<{success: boolean}> {

    const hashedClientToken = createHash('sha256').update(clientToken).digest('hex');
   try { 
        await pool.execute<RowDataPacket[]>
        ("UPDATE refresh_tokens SET valid = 0 WHERE token = ? LIMIT 1", [hashedClientToken]);

        } catch(err) {
            console.warn(`Error revoking a refresh token: ${err}`)
            return {success: false}
        }

        return {success: true}
}