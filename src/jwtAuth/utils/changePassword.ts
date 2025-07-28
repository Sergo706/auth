import { tempJwtLink } from "../../tempLinks.js";
import { LinkTokenPayload } from "../../tempLinks.js";
import { resetPasswordEmail } from "../utils/systemEmailMap.js";
import { getPool } from "../config/dbConnection.js";
import { RowDataPacket } from "mysql2";
import crypto from 'crypto'
import { getLogger } from "../utils/logger.js";
import { getConfiguration } from "../config/configuration.js";

/**
 * @description
 * Sends a password‐reset link via email to a valid registered user.
 *
 * @param {string} email - The user's email address to send the reset link to.
 *
 * @returns {Promise<{ valid: boolean; error?: string }>}
 * Resolves with an object indicating whether the email was sent successfully.
 * If `valid` is false, `error` will contain a descriptive message.
 *
 * @example
 * const result = await sendTempPasswordResetLink('email@example.com');
 * if (result.valid) {
 *   console.log('Reset link sent.');
 * } else {
 *   console.error('Failed to send reset link:', result.error);
 * }
 *
 * @see {@link ./changePassword.js}
 */
export async function sendTempPasswordResetLink(
email: string,
):Promise<{valid: boolean; error?: string}>{
const log = getLogger().child({service: 'auth', branch: 'password-reset'})
const { jwt:  { refresh_tokens }  } = getConfiguration()
log.info('Searching for user email...')
const pool = getPool()
 try { 
 const [results] =  await pool.execute<RowDataPacket[]>(`
    SELECT id, name, email AS user_email, visitor_id
    FROM users
    WHERE email = ?
    `,[email]);

    if (!results || results.length === 0) {
        log.warn('No email is found')
        return {valid: false, error: 'No email found'};
    }
log.info('Found user, generating link and email...')
const { id, name, user_email, visitor_id } = results[0];
const jti = `${crypto.randomUUID()}${crypto.randomBytes(64).toString('hex')}`;

const payload: LinkTokenPayload = {
    visitor: visitor_id,
    subject: "MAGIC_LINK_Restart",
    purpose: "PASSWORD_RESET",
    jti: jti
  };

  const tempToken = tempJwtLink(payload);
  const path = "/auth/reset-password";
  const url = `${refresh_tokens.domain}${path}/${visitor_id}?temp=${encodeURIComponent(tempToken)}`

  await resetPasswordEmail(name, user_email, url)
  log.info({userId: id},'An email for password reset was send to user')
 return {
    valid: true
 };

} catch(err) {
    log.error({err},'Error generating and sending password reset link')
    throw err;
}
    
}