import { tempJwtLink } from "../../tempLinks.js";
import { mfaEmail } from "../utils/systemEmailMap.js";
import { getPool } from "../config/dbConnection.js";
import { RowDataPacket } from "mysql2";
import crypto from 'crypto';
import { getLogger } from "../utils/logger.js";
import { getConfiguration } from "../config/configuration.js";
import { Response } from "express";
import { guard } from "./limiters/utils/guard.js";
import { getLimiters } from "./limiters/protectedEndpoints/emailMfaFlow/email.js";
import { makeConsecutiveCache } from "./limiters/utils/consecutiveCache.js";

const consecutiveForGlobal = makeConsecutiveCache<{countData: number}>(100, 1000 * 60 * 60 * 24);
const consecutiveForUserId = makeConsecutiveCache<{countData: number}>(2000, 1000 * 60 * 60 * 24);
const consecutiveForIp = makeConsecutiveCache<{countData: number}>(2000, 1000 * 60 * 60 * 24);

/**
 * @description
 * Sends a one-time MFA link via email to a valid registered user.
 * Includes rate limiting to prevent email flooding.
 *
 * @param {{ userId: number; visitor: number }} user
 *   The user's identifiers:
 *   - `userId`: the user's unique ID.
 *   - `visitor`: the visitor/session ID.
 * @param {string} sessionToken
 *   The session or refresh token to include in the MFA link.
 * @param {string} ip
 *   The client's IP address for rate limiting.
 * @param {Response} res
 *   Express response object for sending rate limit responses.
 *
 * @returns {Promise<boolean | 'rate_limited'>}
 *   Resolves to `true` if the email was sent successfully, 
 *   `false` if there was an error,
 *   or `'rate_limited'` if rate limited (response already sent).
 *
 * @example
 * const user = { userId: 13, visitor: 14 };
 * const result = await sendTempMfaLink(user, refreshToken, req.ip, res);
 * if (result === 'rate_limited') return; // response already sent
 * if (!result) {
 *   res.status(500).json({ error: 'Could not send MFA code' });
 * }
 *
 * @see {@link ./emailMFA.js}
 */
export async function sendTempMfaLink(
  user: { userId: number; visitor: number },
  sessionToken: string,
  ip: string,
  res: Response
): Promise<boolean | 'rate_limited'> {
  const { magic_links } = getConfiguration();
  const { globalEmailLimiter, userIdLimiter, ipLimiter } = getLimiters();
  const log = getLogger().child({ service: 'auth', branch: 'mfa', visitorId: user.visitor });

  if (!(await guard(globalEmailLimiter, 'global_emails', consecutiveForGlobal, 1, 'globalEmailLimiter', log, res))) {
    return 'rate_limited';
  }

  if (!(await guard(userIdLimiter, `user_${user.userId}`, consecutiveForUserId, 2, 'userIdLimiter', log, res))) {
    return 'rate_limited';
  }

  if (!(await guard(ipLimiter, ip, consecutiveForIp, 2, 'ipLimiter', log, res))) {
    return 'rate_limited';
  }

  const jti = `${crypto.randomUUID()}${crypto.randomBytes(64).toString('hex')}`;
  const tempToken = tempJwtLink({
    visitor: user.visitor,
    subject: 'MAGIC_LINK_MFA_CHECKS',
    purpose: 'MFA',
    jti: jti
  });

  log.info(`Entered mfa, generating temp link...`);
  const path = "/auth/verify-mfa";
  const url = `${magic_links.domain}${path}/${user.visitor}?temp=${encodeURIComponent(tempToken)}`;

  log.info(`Generating mfa code...`);
  const randomCode = crypto.randomInt(1000000, 9999999).toString().padStart(7, '0');
  const hashedCode = crypto.createHash("sha256").update(randomCode).digest("hex");
  const expires = new Date(Date.now() + 7 * 60 * 1000);
  const hashedClientToken = crypto.createHash('sha256').update(sessionToken).digest('hex');
  const params = [user.userId, hashedClientToken, jti, hashedCode, expires];
  const pool = getPool();
  const conn = await pool.getConnection();

  try { 
    
    await conn.beginTransaction();  

  const [exits] = await conn.execute<RowDataPacket[]>(`
    SELECT code_hash FROM mfa_codes
     WHERE user_id = ?
     AND token = ?
     AND expires_at > UTC_TIMESTAMP()
  `, [user.userId, hashedClientToken]);


    if (exits.length > 0) {
      log.info(`Valid MFA code found for user ${user.userId}: ${exits[0].code_hash}`)
      await conn.commit();
      conn.release();
      return true;
    };

      await conn.execute(`
      DELETE FROM mfa_codes
      WHERE user_id = ?
    `, [user.userId]);    

   await conn.execute<RowDataPacket[]>(`
    INSERT INTO mfa_codes
    (user_id, token, jti, code_hash, expires_at)
    VALUES (?, ?, ?, ?, ?)
    `,params);
    await conn.commit();
   log.info(`Generated code`)
  
} catch(err) {
    log.error({err}, `error Generating code`)
    await conn.rollback();
    conn.release();
    return false;
} 
conn.release();
try {
  log.info(`Sending email...`)
  const [rows] = await pool.execute<RowDataPacket[]>(`SELECT name, email FROM users WHERE id = ?`, [user.userId]);
  const { name, email } = rows[0];
  await mfaEmail(name, Number(randomCode), email, url);
  log.info(`email sended.`)
  return true;
} catch (err) {
    log.error({err},`SMTP error in sendTempMfaLink`)
    return false;
  }
 }
