import { NextFunction, Request, Response } from 'express';
import { getPool } from '../config/dbConnection.js';
import { ResultSetHeader, RowDataPacket } from "mysql2";
import crypto from 'crypto';
import { code as codeSchema } from '../models/zodSchema.js'
import { generateRefreshToken, revokeRefreshToken, verifyRefreshToken } from '../../refreshTokens.js';
import { generateAccessToken } from '../../accessTokens.js';
import { getConfiguration } from '../config/configuration.js';
import { makeCookie } from '../utils/cookieGenerator.js';
import { validateSchema } from '../utils/validateZodSchema.js';
import { guard } from "../utils/limiters/utils/guard.js";
import { getLimiters, resetLimitersUni } from "../utils/limiters/protectedEndpoints/tempPostRoutesLimiter.js";
import { makeConsecutiveCache } from "../utils/limiters/utils/consecutiveCache.js"
import { updateVisitors } from '@riavzon/botdetector';
import pino from 'pino';

const consecutiveForSubmittedHash = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 10);
const consecutiveForSlowDown = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 10);
export const consecutiveForJti = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 20);

/**
 * Core utility for verifying Multi-Factor Authentication (MFA) codes.
 * 
 * @description
 * This function performs the actual verification of a submitted MFA code:
 * 1. **Rate Limiting**: Guards against brute-force attacks using IP and session-based limiters.
 * 2. **Code Hashing**: Hashes the submitted code and compares it with the stored hash in the database.
 * 3. **Database Transaction**:
 *    - Finds a valid, unexpired, and unused code for the given session (JTI).
 *    - Deletes the code upon successful verification (atomic consumption).
 *    - Updates the user's `last_mfa_at` and visitor status.
 * 4. **Token Rotation**: Revokes the current refresh token and generates a new pair (Access + Refresh).
 * 5. **Fingerprint Update**: Updates the visitor's fingerprint using the latest request data.
 * 
 * @param {Request} req - Express request object. 
 * Must contain `req.link` (visitor, subject, purpose, jti) and `req.fingerPrint`.
 * @param {Response} res - Express response object.
 * @param {NextFunction} next - Express next function.
 * @param {string} code - The MFA code submitted by the user.
 * @param {pino.Logger} log - Logger instance for tracing.
 * 
 * @returns {Promise<void>}
 * 
 * @example
 * await verifyMfaCode(req, res, next, '123456', logger);
 */
export async function verifyMfaCode(req: Request, res: Response, next: NextFunction, code: string, log: pino.Logger) {

    const { uniLimiter, ipLimit, usedJtiLimiter  } = getLimiters();
    const { jwt } = getConfiguration();
    const fingerprints = req.fingerPrint;
    log.info(`Verifying mfa code...`)

    const verify = async (req: Request, res: Response, next: NextFunction) => {

         if (!(await guard(uniLimiter, req.ip!, consecutiveForSlowDown, 2, 'SlowDown', log, res))) return;
         if (!(await guard(uniLimiter, req.link.jti!, consecutiveForJti, 1,'jti', log, res))) return;

        const result = await validateSchema(codeSchema, { code }, req, log)

        if ("valid" in result) { 
            if (!result.valid && result.errors !== 'XSS attempt') {
                res.status(400).json(Object.assign({error: result.errors,  "banned": false }))
                return;
            }
            res.status(403).json({"banned": true})
            return; 
        }  

        if (!result.success) {
          log.error({ errors: result.error }, "Zod validation failed")
          res.status(400).json({ 
              ok: false,
              date: new Date().toISOString(), 
              reason: "Zod validation failed malformed link"
           })
          return;
     }
       const {code: validatedCode} = result.data;
       const submittedHash = crypto.createHash("sha256").update((validatedCode)).digest("hex");

       if (!(await guard(ipLimit, submittedHash, consecutiveForSubmittedHash, 1,'submittedHash', log, res))) return;
       const { jti, visitor } = req.link;

       if (!jti) {
            log.warn(`No Session Token`)
            res.status(500).json({ error: 'No Session Token' });
            return;
        }
      const pool = getPool()
      const conn = await pool.getConnection();

      try { 
        await conn.beginTransaction();
       const [rows] = await conn.execute<RowDataPacket[]>(`
          SELECT token, user_id 
            FROM mfa_codes
             WHERE jti        = ?
               AND code_hash  = ?
               AND expires_at > UTC_TIMESTAMP()
               AND used       = 0
            FOR UPDATE
          `,[jti, submittedHash])
      
          if (!rows || rows.length === 0) {
          log.warn(`Invalid or expired code.`)
          await conn.rollback();
          res.status(401).json({ error: 'Invalid or expired code.' });
          return;
          }
      
       const [DELETE] = await conn.execute<ResultSetHeader>(`
            DELETE FROM mfa_codes
             WHERE jti        = ?
               AND user_id    = ?
               AND code_hash  = ?
               AND expires_at > UTC_TIMESTAMP()
               AND used       = 0
            LIMIT 1
          `,[jti, rows[0].user_id, submittedHash])
             
          if (DELETE.affectedRows !== 1) {
          log.warn(`Invalid or expired code.`)
          await conn.rollback();
          res.status(401).json({ error: 'Invalid or expired code.' });
          return;
          }
         await ipLimit.block(submittedHash, 60 * 10);
      
        log.info(`Found valid code, updating users and visitors...`)
        const currentVisitorId = req.newVisitorId || visitor;
      
        if (!currentVisitorId ) {
          log.fatal(`currentVisitorId  is empty, possible loop`)
          res.status(500).json({error: `currentVisitorId  is empty, possible loop`});
          return;
      } 
          await conn.execute(`
        UPDATE users
        JOIN visitors
          ON visitors.visitor_id = ?
        SET
          users.visitor_id     = visitors.visitor_id,
          users.last_mfa_at    = UTC_TIMESTAMP(),
          visitors.proxy_allowed   = 1,
          visitors.hosting_allowed = 1
        WHERE
          users.id = ?
        `,
          [currentVisitorId, rows[0].user_id]    
        );
      
        await usedJtiLimiter.block(jti, 60 * 20);
        await conn.commit();
        consecutiveForSlowDown.delete(req.ip!);
        consecutiveForJti.delete(jti!);
        consecutiveForSubmittedHash.delete(submittedHash!);
        await resetLimitersUni(req.ip!);
        
        const updateFingerPrint = await updateVisitors({
            userAgent: fingerprints.userAgent,
            ipAddress: fingerprints.ipAddress,
            country: fingerprints.country ?? '',
            region: fingerprints.region ?? '',
            regionName: fingerprints.regionName ?? '',
            city: fingerprints.city ?? '',
            district: fingerprints.district ?? '',
            lat: fingerprints.lat !== undefined ? String(fingerprints.lat) : '',
            lon: fingerprints.lon !== undefined ? String(fingerprints.lon) : '',
            timezone: fingerprints.timezone ?? '',
            currency: fingerprints.currency ?? '',
            isp: fingerprints.isp ?? '',
            org: fingerprints.org ?? '',
            as: fingerprints.as_org ?? '',
            device_type: fingerprints.device,
            browser: fingerprints.browser,
            proxy: fingerprints.proxy ?? false,
            hosting: fingerprints.hosting ?? false,
            deviceVendor: fingerprints.deviceVendor,
            deviceModel: fingerprints.deviceModel,
            browserType: fingerprints.browserType,
            browserVersion: fingerprints.browserVersion,
            os: fingerprints.os
          }, req.cookies.canary_id, currentVisitorId);
        
          if (!updateFingerPrint.success) {
             log.error({error: updateFingerPrint.reason},`Failed to update fingerprints, false positives may occur.`);
          }
      
       log.info(`updated users and visitors, generating tokens...`)
        const token = rows[0].token;
        const userId = rows[0].user_id;
      
      
        const result = await verifyRefreshToken(token);
        if (!result.valid) {
          log.warn(`invalid refresh token: ${result.reason}`)
           res.status(401).json({ error: result.reason });
          return;
        }
        
         const {success} = await revokeRefreshToken(token);
         
          if (!success) {
            log.error(`Error Revoking refresh token`)
          res.status(500).json({ error: `Error Revoking refresh token` });
          return;
          }
      
        const accessToken = generateAccessToken({
          id:         userId,
          visitor_id: currentVisitorId,
          jti: crypto.randomUUID() 
        });
        
          const newRefresh = await generateRefreshToken(
          jwt.refresh_tokens.refresh_ttl,
          userId
        );
      
        makeCookie(res, 'iat', Date.now().toString(), {
            httpOnly: true,
            secure:   true,
            sameSite: 'strict',
            path:     '/',
            expires: newRefresh!.expiresAt,
            });
      
        makeCookie(res, 'session', newRefresh!.raw, {
           httpOnly: true,
           sameSite: "strict", 
           expires: newRefresh!.expiresAt,
           secure: true,
           domain: jwt.refresh_tokens.domain,
           path: '/'
        })
          log.info(`MFA Verified! and new tokens are set`)
          res.status(200).json({ accessToken: accessToken, accessIat: Date.now().toString() });
          return;
      
      } catch(err) {
          await conn.rollback();
          log.error({err},`MFA verify error`)
          res.status(500).json({ error: 'Internal server error' });
          return;
      } finally {
        conn.release();
      }
    }
    return verify(req, res, next)
}