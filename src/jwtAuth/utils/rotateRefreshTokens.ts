import { ResultSetHeader } from "mysql2";
import { generateRefreshToken, revokeRefreshToken, verifyRefreshToken } from "../../refreshTokens.js";
import { getPool } from "../config/dbConnection.js";
import { ensureSha256Hex, toDigestHex } from "./hashChecker.js";
import { getLogger } from "./logger.js";
import crypto from 'node:crypto'

/**
 * Rotate a one‑use refresh token: verify the presented token, revoke it,
 * and issue a fresh refresh token with a new expiry.
 *
 * This helper is intended for flows where a refresh token should be consumed
 * (invalidated) whenever it is used, ensuring tokens cannot be replayed.
 * The function accepts a raw (unhashed) token; hashing and validation are
 * handled internally.
 *
 * @param {number} ttl - Time to live for the newly issued refresh token in milliseconds.
 * @param {number} userId - The user id expected to own the current token.
 * @param {string} oldClientToken - The current (raw) refresh token to rotate.
 *
 * @returns {Promise<{ rotated: boolean; raw?: string; expiresAt?: Date }>} Resolves with
 * the rotation result. When `rotated === true`, `raw` contains the newly issued token
 * and `expiresAt` its expiration time. When `rotated === false`, the token was not
 * rotated (e.g., invalid, mismatched user, or revoke failure).
 *
 * @throws {Error} Propagates database errors from verification, revocation,
 * or token issuance operations.
 *
 * @example
 * const result = await rotateOneUseRefreshToken(1000 * 60 * 60 * 24 * 7, user.id, req.body.refreshToken);
 * if (!result.rotated) {
 *   // handle invalid or unrotated token
 * }
 * // issue result.raw to the client and persist as needed
 *
 * @see {@link ../../refreshTokens.js generateRefreshToken}
 * @see {@link ../../refreshTokens.js verifyRefreshToken}
 * @see {@link ../../refreshTokens.js revokeRefreshToken}
 */
export async function rotateOneUseRefreshToken(ttl: number, userId: number, oldClientToken: string): 
 Promise<{
    rotated: boolean,
    raw?: string;
    expiresAt?: Date;
 }> {

const log = getLogger().child({service: 'auth', branch: 'refresh tokens'})

    log.info({userId},'generating and rotating new refresh tokens...')

    const {valid, reason, userId: tokenUserId} = await verifyRefreshToken(oldClientToken);

    if (!valid) {
        log.warn({userId, reason: reason},'Token not rotated, old token is not valid');
             return {
                rotated: false
            }
    }

    if (userId !== tokenUserId) {
        log.warn({userId},'Token not rotated, user id is malformed');
             return {
                rotated: false
        }
    }
     const revoked = await revokeRefreshToken(oldClientToken);
     if (!revoked.success) {
        log.warn({userId},`Token not rotated, couldn't revoke the old token`);
            return {
              rotated: false
        }
     }

     const token = await generateRefreshToken(ttl, userId)
     const expiresAt = token.expiresAt;

     log.info({userId},'Rotated refresh token')
 return {
     rotated: true,
     raw: token.raw,
     expiresAt: expiresAt
 }
}


/**
 * Rotate an expired refresh token in place by updating its existing row with
 * a new token and refreshed expiry, re‑enabling it for use.
 *
 * This operation only succeeds if the provided token:
 * - belongs to the specified `userId`,
 * - is currently invalid (`valid = 0`), and
 * - is expired (`expiresAt <= UTC_TIMESTAMP()`).
 *
 * The function accepts the raw (unhashed) token, hashing is handled internally.
 *
 * Security note: in place rotation of expired tokens relaxes stricter models
 * that require issuing a new row after expiry. 
 * Ensure higher level logic still
 * enforces maximum session lifetime, anomaly/MFA checks, and that the token is verified and/or the invalidity reason of it, is expiry, before using this function.
 *
 *
 * @param {number} ttl - Time to live in milliseconds for the new token value.
 * @param {number} userId - The user who owns the token being rotated.
 * @param {string} oldClientToken - The current raw refresh token to replace.
 *
 * @returns {Promise<{ rotated: boolean; raw?: string; expiresAt?: Date }>} When
 * `rotated === true`, returns the new raw token and its expiration. When
 * `rotated === false`, the token could not be updated in place.
 *
 * @throws {Error} If a database error occurs during the update.
 *
 * @example
 * const res = await rotateInPlaceRefreshToken(7*24*60*60*1000, user.id, req.cookies.session);
 * if (res.rotated) {
 *   // set cookie with res.raw and res.expiresAt
 * }
 */
export async function rotateInPlaceRefreshToken(ttl: number, userId: number, oldClientToken: string): Promise<{
    rotated: boolean,
    raw?: string;
    hashedToken?: string;
    expiresAt?: Date;
}> {
const log = getLogger().child({service: 'auth', branch: 'refresh tokens'})
const pool = getPool()  
log.info({userId},'generating and rotating new refresh tokens...')
    const token = crypto.randomBytes(64).toString('hex');
    const {input: hashedToken} = await toDigestHex(token)
    const expiresAt = new Date(Date.now() + ttl);

    const { input: maybeDigest } = await toDigestHex(oldClientToken);  
    const oldHashedClientToken = ensureSha256Hex(maybeDigest);    

    try {
        const [rotate] = await pool.execute<ResultSetHeader>(`
            UPDATE refresh_tokens
             SET 
              token = ?,
              expiresAt = DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND),
              valid = 1
            WHERE 
              token = ?
              AND user_id = ?
              AND valid = 0
              AND expiresAt <= UTC_TIMESTAMP() 
            `,[hashedToken, Math.floor(ttl / 1000), oldHashedClientToken, userId]); 
           
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
     expiresAt: expiresAt
 }
  }
