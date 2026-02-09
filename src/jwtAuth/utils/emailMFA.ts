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
import { generateMfaCode } from "./secureRandomCode.js";
import { EmailMetaDataOTP } from "../types/Emails.js";
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
  res: Response,
  meta: EmailMetaDataOTP
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

try {
  const { ok, data, code, date } = await generateMfaCode(log, sessionToken, user.userId, jti)
  
  if (data === 'Code exists') {
    log.info(`Valid MFA code found for user ${user.userId}`)
    return true;
  }

  if (!ok || !code) {
      log.warn({ data, ok, date }, "Error generating new mfa code.");
      return false
  }
  
  const pool = getPool()
  log.info(`Sending email...`)
  const [rows] = await pool.execute<RowDataPacket[]>(`SELECT name, email FROM users WHERE id = ?`, [user.userId]);
  const { name, email } = rows[0];
  await mfaEmail(Number(code), email, url, meta);
  log.info(`email sended.`)
  return true;
} catch (err) {
    log.error({err},`SMTP error in sendTempMfaLink`)
    return false;
  }
 }
