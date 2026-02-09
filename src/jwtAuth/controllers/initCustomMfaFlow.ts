import { NextFunction, Request, Response } from 'express';
import { getLogger } from '../utils/logger.js';
import { validateSchema } from '../utils/validateZodSchema.js';
import {  getLimiters, resetLimitersUni } from "../utils/limiters/protectedEndpoints/passwordResetFlow/initPasswordResetLimiter.js";
import { makeConsecutiveCache } from '../utils/limiters/utils/consecutiveCache.js';
import { guard } from '../utils/limiters/utils/guard.js';
import { getLimiters as getEmailLimiters } from "../utils/limiters/protectedEndpoints/emailMfaFlow/email.js";
import { getConfiguration } from '../config/configuration.js';
import { schema } from '../types/CustomMfaSchema.js';
import { generateCustomMfaFlow } from '../utils/customMfaLinks.js';
import { waitSomeTime } from '../utils/timeEnum.js';
import { EmailMetaDataOTP } from '../types/Emails.js';

  const consecutiveForIp = makeConsecutiveCache< {countData:number} >(2000, 1000 * 24 * 60 * 60);
  const consecutiveForEmail = makeConsecutiveCache< {countData:number} >(2000, 1000 * 24 * 60 * 60);
  const consecutiveForCompositeKey = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 30);
  const consecutiveForGlobal = makeConsecutiveCache<{countData: number}>(100, 1000 * 60 * 60 * 24);

/**
 * Initializes a custom MFA flow for an authenticated user.
 * 
 * @description
 * This controller handles the initiation of a Multi-Factor Authentication (MFA) process.
 * It performs several security checks before generating a code:
 * 1. **IP Restriction**: Only allowed IPs (based on configuration) can access this endpoint.
 * 2. **Global Rate Limiting**: Prevents abuse of the entire MFA system.
 * 3. **IP/Email Rate Limiting**: Prevents brute-forcing or spamming for a specific user/IP.
 * 4. **Session Anomaly Detection**: Uses `strangeThings` to verify session health and detect anomalies.
 * 5. **Timing Protection**: Ensures a consistent response time (approx. 3s) to prevent timing attacks.
 * 
 * @param {Request} req - Express request object. 
 * Expected query: `rand` (min 254 chars).
 * Expected params: `reason` (purpose of MFA).
 * Expected cookies: `canary_id`, `session` (refresh token).
 * @param {Response} res - Express response object.
 * @param {NextFunction} next - Express next function.
 * 
 * @returns {Promise<void>}
 * 
 * @example
 * // Initiate MFA for login
 * // POST /custom/mfa:login?rand=a...a (300 chars)
 * // Cookie: session=...; canary_id=...
 */
export async function initCustomMfaFlow(req: Request, res: Response, next: NextFunction) {
  const { uniLimiter, ipLimiter, emailLimiter } = getLimiters();
  const { globalEmailLimiter } = getEmailLimiters();
  const { service } = getConfiguration();
  const log = getLogger().child({service: 'auth', branch: 'custom-mfa'})

  const trustedClientIp = service?.clientIp ?? service?.proxy.ipToTrust;
  let physicalIp = req.socket.remoteAddress || '';

  if (physicalIp.startsWith('::ffff:')) {
      physicalIp = physicalIp.substring(7);
  }

  if (!trustedClientIp || physicalIp !== trustedClientIp) {
    log.warn('Not allowed ip access attempt')
    res.status(403).json({
        ok: false,
        date: new Date().toISOString(),
        reason: 'Forbidden'
    });
    return;
  }

  log.info('Starting custom mfa flow process...');
  const start = Date.now();
 try {

    if (!req.is('application/json')) {
      log.info('Content type is not json!')
      res.status(400).json({error: 'Bad Request.'})
      return; 
    }

    if (!(await guard(globalEmailLimiter, 'global_emails', consecutiveForGlobal, 1, 'globalEmailLimiter', log, res))) return;
    

    if (!(await guard(ipLimiter, req.ip!, consecutiveForIp, 2, 'ip', log, res))) return;

    const random = req.query.random;
    const reason = req.params.reason;
    const canary = req.cookies.canary_id;
    const refresh = req.cookies.session;

    if (!random || !reason || !canary || !refresh) {
        res.status(400).json({
            ok: false,
            date: new Date().toISOString(), 
            reason: "Missing signature" 
        })
        return;
    }
    const result = await validateSchema(schema, { random, reason }, req, log)
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
            reason: "Zod validation failed"
         })
        return;
    }
    const { random: validRandom, reason: validReason } = result.data;

    const compositeKey = `${req.ip!}_${validRandom}_${validReason}`;    
    if (!(await guard(emailLimiter, `${validRandom}_${validReason}`, consecutiveForEmail, 2, 'email', log, res))) return;
    if (!(await guard(uniLimiter, compositeKey, consecutiveForCompositeKey, 3, 'ip+random+reason', log, res))) return;

    log.info(`Using verified session from protectRoute...`)
    const { userId, visitor_id: visitorId } = req.user!;

    log.info({ userId, visitorId }, `Verified session health, initiating MFA...`);
    const { device, os, browser, city, country, browserType} = req.fingerPrint;

    const meta: EmailMetaDataOTP = {
        device: `${device ?? 'Unknown Device'}-${os ?? ''}-${req.ip!}`.trim(),
        browser: `${browser ?? 'Unknown Browser'}-${browserType ?? ''}`.trim(),
        location: `${country ?? 'Unknown Location'}-${city ?? ''}`.trim()
    }
    const { ok, data } = await generateCustomMfaFlow(
        validRandom,
        validReason, 
        { userId: Number(userId)!, visitor: Number(visitorId)! },
         refresh,
         req.ip!,
        res,
        meta
      )

    if (!ok && data === 'rate_limited') return;
    
    if (!ok && data === 'exists') {
        log.warn({data, reason}, "Duplicate reason provided!")
        res.status(400).json({
            ok: false,
            date: new Date().toISOString(),
            reason: 'This reason is already in use internally please provide a different one.'
        })
        return;
    }    
    if (!ok) {
       log.error({data}, "Error generating new mfa flow")
       res.status(500).json({ 
        ok: false, 
        date: new Date().toISOString(), 
        reason: "Error generating new mfa code." 
     });
     return;
    }
     consecutiveForIp.delete(req.ip!)
     consecutiveForEmail.delete(`${validRandom}_${validReason}`);
     consecutiveForCompositeKey.delete(compositeKey)
     await resetLimitersUni(compositeKey);
     log.info(`MFA flow was started successfully.`)
    res.status(200).json({
        ok: true,
        date: new Date().toISOString(), 
        data: "success" 
    })
 } catch(err) {
    log.error({err}, "Unexpected error generating mfa flow.")
 } finally {
    const elapsed = Date.now() - start;
    const delay = 3000;
    if (elapsed < delay) {
      await waitSomeTime(delay - elapsed, log);
    }
    if (!res.headersSent) {
      res.status(200).json({
        ok: true,
        date: new Date().toISOString(),
        data: "success"
      });
    }
 }
}