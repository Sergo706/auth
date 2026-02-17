import { tempJwtLink } from "../../tempLinks.js";
import { getPool } from "../config/dbConnection.js";
import { RowDataPacket } from "mysql2";
import crypto from 'crypto'
import { getLogger } from "../utils/logger.js";
import { getConfiguration } from "../config/configuration.js";
import { Response } from "express";
import { getLimiters } from "./limiters/protectedEndpoints/emailMfaFlow/email.js";
import { guard } from "./limiters/utils/guard.js";
import { makeConsecutiveCache } from "./limiters/utils/consecutiveCache.js";
import { toDigestHex } from "./hashChecker.js";
import { generateMfaCode } from "./secureRandomCode.js";
import { mfaEmail } from "./systemEmailMap.js";
import { EmailMetaDataOTP } from "../types/Emails.js";

const consecutiveForGlobal = makeConsecutiveCache<{countData: number}>(100, 1000 * 60 * 60 * 24);
const consecutiveForUserId = makeConsecutiveCache<{countData: number}>(2000, 1000 * 60 * 60 * 24);
const consecutiveForIp = makeConsecutiveCache<{countData: number}>(2000, 1000 * 60 * 60 * 24);

/**
 * Generates a custom MFA flow, including a magic link and an MFA code.
 * 
 * @description
 * This utility manages the internal logic for starting a custom MFA process:
 * 1. **Reserved Reason Check**: Prevents collision with internal reasons (`MFA`, `PASSWORD_RESET`, etc.).
 * 2. **Multi-layer Rate Limiting**: Global, User ID, and IP based guards.
 * 3. **Magic Link Generation**: Creates a TEMPORARY JWT containing the `randomHashed` value and a unique `jti`.
 * 4. **MFA Code Storage**: Uses `generateMfaCode` to securely store the session-linked MFA code in the DB.
 * 5. **Email Delivery**: Sends a generic MFA email with the generated URL.
 * 
 * @param {string} random - A high-entropy random string (min 254 chars) used for verification.
 * @param {string} reason - The specific purpose for this MFA flow (e.g., 'delete_account').
 * @param {object} user - Information about the user.
 * @param {number} user.userId - Database ID of the user.
 * @param {number} user.visitor - Database ID of the visitor.
 * @param {string} sessionToken - Current refresh token string to link the MFA code to.
 * @param {string} ip - IP address of the requester for rate limiting.
 * @param {Response} res - Express response object (for rate limiting headers).
 * 
 * @returns {Promise<{ ok: boolean; date: string; data: string }>} Result of the operation.
 * 
 * @example
 * const result = await generateCustomMfaFlow(
 *   longRandomString,
 *   'sensitive_action',
 *   { userId: 1, visitor: 123 },
 *   refreshToken,
 *   '127.0.0.1',
 *   res
 * );
 * if (result.ok) console.log('MFA flow started');
 */
export async function generateCustomMfaFlow(
    random: string,
    reason: string,
    user: { userId: number; visitor: number },
    sessionToken: string,
    ip: string,
    res: Response,
    meta: EmailMetaDataOTP
) {
      const { magic_links } = getConfiguration();
      const { globalEmailLimiter, userIdLimiter, ipLimiter } = getLimiters();
      const log = getLogger().child({ service: 'auth', branch: 'mfa', visitorId: user.visitor, reason });

      if (reason === "MAGIC_LINK_MFA_CHECKS" || reason === "PASSWORD_RESET" || reason === "PASSWORD_RESET_FLOW" || reason === "EMAIL_MFA_FLOW") {
        return {
            ok: false,
            date: new Date().toISOString(),
            data: 'exists'
        }
      } 
      
      if (!(await guard(globalEmailLimiter, 'global_emails', consecutiveForGlobal, 1, 'globalEmailLimiter', log, res))) {
          return {
            ok: false,
            date: new Date().toISOString(),
            data: 'rate_limited'
          };
        }
      
      if (!(await guard(userIdLimiter, `user_${user.userId}`, consecutiveForUserId, 2, 'userIdLimiter', log, res))) {
          return {
            ok: false,
            date: new Date().toISOString(),
            data: 'rate_limited'
          };
        }
      
      if (!(await guard(ipLimiter, ip, consecutiveForIp, 2, 'ipLimiter', log, res))) {
          return {
            ok: false,
            date: new Date().toISOString(),
            data: 'rate_limited'
          };
      }
    const jti = `${crypto.randomUUID()}${crypto.randomBytes(64).toString('hex')}`;
    const { input: randomHashed } = await toDigestHex(random);

    const tempToken = tempJwtLink({
          visitor: user.visitor,
          subject: `${reason}_${user.visitor}`,
          purpose: reason,
          randomHashed,
          jti: jti
        });
    log.info(`Entered mfa, generating temp link...`);
    const { pathForCustomFlow } = magic_links.paths
    const url = new URL(pathForCustomFlow, magic_links.domain)
    url.searchParams.set('visitor', String(user.visitor))
    url.searchParams.set('token', tempToken);
    url.searchParams.set('random', random);
    url.searchParams.set('reason', reason);
    
    try {
        const { ok, data, date, code } = await generateMfaCode(log, sessionToken, user.userId, jti);

        if (data === 'Code exists') {
            return {
                ok: true,
                date: new Date().toISOString(),
                data: "A valid code already exists. Please check your email."
            }
        }

        if (!ok || !code) {
            log.warn({ data, ok, date }, "Error generating new mfa code.");
            return {
                ok: false,
                date: new Date().toISOString(),
                data: data
            }
        }

        log.info("Sending email...")
        const pool = getPool()
        const [rows] = await pool.execute<RowDataPacket[]>(`SELECT email FROM users WHERE id = ?`, [user.userId]);

        if (!rows.length) {
            log.warn("Failed to find user email and name.")
            return {
                ok: false,
                date: new Date().toISOString(),
                data: "User not found"
            }
        }

        const { email } = rows[0];
        await mfaEmail(Number(code), email, url.toString(), meta) 
        log.info(`Email sended.`)
        return {
            ok: true,
            date: new Date().toISOString(),
            data: "Please check your email to continue the action."
        }
    } catch (err) {
        log.error({err}, `Error Starting an mfa flow`)
        return {
            ok: false,
            date: new Date().toISOString(),
            data: "Unexpected error"
        }
    }
}