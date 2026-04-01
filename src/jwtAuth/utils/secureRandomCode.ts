import crypto from 'node:crypto'
import pino from 'pino';
import { getPool } from '../config/configuration.js';
import { RowDataPacket } from 'mysql2';

/**
 * Generates and stores a cryptographically secure MFA code for a user session.
 * 
 * @description
 * This is the centralized utility for MFA code generation:
 * 1. **Idempotency**: It first checks if a valid, unexpired code already exists for the user/session.
 *    If one exists, it returns `ok: false` with `data: 'Code exists'` to avoid spamming or overwriting valid codes.
 * 2. **Cleanup**: Before inserting a NEW code, it deletes any existing codes for the user to ensure single-code-at-a-time logic.
 * 3. **Secure Generation**: Uses `crypto.randomInt` to generate a 7-digit numeric code.
 * 4. **Hashed Storage**: Stores the code as a SHA-256 hash in the `mfa_codes` table, linked to a session `jti` and a hashed version of the `sessionToken`.
 * 5. **Transaction Integrity**: Uses a MySQL transaction to ensure the double deletion/insertion is atomic.
 * 
 * @param {pino.Logger} log - Logger instance.
 * @param {string} sessionToken - The raw session (refresh) token string to bind the code to.
 * @param {string | number} userId - Database ID of the user.
 * @param {string} jti - Unique identifier for the current MFA flow/session.
 * 
 * @returns {Promise<{ok: boolean, date: string, code?: string, data: string}>}
 * If `ok` is true, the `code` field contains the raw numeric code to be sent to the user.
 * 
 * @example
 * const result = await generateMfaCode(log, refreshToken, 1, 'unique-flow-jti');
 * if (result.ok) {
 *   console.log(`Code to send: ${result.code}`);
 * } else if (result.data === 'Code exists') {
 *   console.log('Skipping generation, code already active.');
 * }
 */
export async function generateMfaCode(log: pino.Logger, sessionToken: string, userId: string | number, jti: string): 
Promise<{ok: boolean, date: string, code?: string, data: string}> {

    log.info(`Generating mfa code...`);
    const randomCode = crypto.randomInt(1000000, 9999999).toString().padStart(7, '0');
    const hashedCode = crypto.createHash("sha256").update(randomCode).digest("hex");
    const expires = new Date(Date.now() + 7 * 60 * 1000);
    const hashedClientToken = crypto.createHash('sha256').update(sessionToken).digest('hex');
    const params = [userId, hashedClientToken, jti, hashedCode, expires];
    const pool = getPool();
    const conn = await pool.getConnection();

    
    try { 
    
        await conn.beginTransaction();  

        const [exits] = await conn.execute<RowDataPacket[]>(`
            SELECT code_hash FROM mfa_codes
            WHERE user_id = ?
            AND token = ?
            AND expires_at > UTC_TIMESTAMP()
        `, [userId, hashedClientToken]);


            if (exits.length > 0) {
            log.info(`Valid MFA code found for user ${userId}: ${exits[0].code_hash}`)
            await conn.commit();
            return {
                ok: false,
                date: new Date().toISOString(),
                data: 'Code exists'
            }
            };

            await conn.execute(`
            DELETE FROM mfa_codes
            WHERE user_id = ?
            `, [userId]);    

        await conn.execute<RowDataPacket[]>(`
            INSERT INTO mfa_codes
            (user_id, token, jti, code_hash, expires_at)
            VALUES (?, ?, ?, ?, ?)
            `,params);
            await conn.commit();
            
        log.info(`Generated code`)
        return {
            ok: true,
            date: new Date().toISOString(),
            code: randomCode,
            data: "Generated code"
        }
    } catch(err) {
        log.error({err}, `error Generating code`)
        await conn.rollback();
        return {
            ok: false,
            date: new Date().toISOString(),
            data: "Unexpected error"
        }
    } finally {
        conn.release();
    } 
}