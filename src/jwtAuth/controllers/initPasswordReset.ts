import { NextFunction, Request, Response } from 'express';
import { email } from '../models/zodSchema.js';
import { sendTempPasswordResetLink } from '../utils/changePassword.js';
import { getLogger } from '../utils/logger.js';
import { validateSchema } from '../utils/validateZodSchema.js';
import {  getLimiters, resetLimitersUni } from "../utils/limiters/protectedEndpoints/passwordResetFlow/initPasswordResetLimiter.js";
import { makeConsecutiveCache } from '../utils/limiters/utils/consecutiveCache.js';
import { guard } from '../utils/limiters/utils/guard.js';
import { waitSomeTime } from '../utils/timeEnum.js';
import { getLimiters as getEmailLimiters } from "../utils/limiters/protectedEndpoints/emailMfaFlow/email.js";

  const consecutiveForIp = makeConsecutiveCache< {countData:number} >(2000, 1000 * 24 * 60 * 60);
  const consecutiveForEmail = makeConsecutiveCache< {countData:number} >(2000, 1000 * 24 * 60 * 60);
  const consecutiveForCompositeKey = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 30);
  const consecutiveForGlobal = makeConsecutiveCache<{countData: number}>(100, 1000 * 60 * 60 * 24);

/**
 * Begin the password reset flow for a given email.
 *
 * Behavior:
 * - Requires `application/json` body with a valid email.
 * - Applies IP/email/composite-key rate limits.
 * - Always responds with 200 and a generic success message if no error occurred
 *   earlier, after an artificial minimum delay to avoid enumeration timing.
 *
 * Responses prior to the uniform 200:
 * - 400: Schema errors or bad content type.
 * - 403: Banned/XSS attempt signaled by validator.
 */
export const initPasswordReset = async (req: Request, res: Response, next: NextFunction) => {
  const { uniLimiter, ipLimiter, emailLimiter } = getLimiters();
  const { globalEmailLimiter } = getEmailLimiters();

  const log = getLogger().child({service: 'auth', branch: 'password-reset'})
  log.info('Starting password reset process...');
  const start = Date.now();
  try { 

    if (!req.is('application/json')) {
      log.info('Content type is not json!')
      res.status(400).json({error: 'Bad Request.'})
      return; 
    }
     
    if (!(await guard(globalEmailLimiter, 'global_emails', consecutiveForGlobal, 1, 'globalEmailLimiter', log, res))) return;
    

    if (!(await guard(ipLimiter, req.ip!, consecutiveForIp, 2, 'ip', log, res))) return;

    
  const result = await validateSchema(email, req.body, req, log)
 
 if ("valid" in result) { 
     if (!result.valid && result.errors !== 'XSS attempt') {
        res.status(400).json(Object.assign({error: result.errors,  "banned": false }))
        return;
     }
     res.status(403).json({"banned": true})
     return; 
 } 

  const validetedEmail = result.data!.email
  const compositeKey = `${req.ip!}_${validetedEmail}`;

  if (!(await guard(emailLimiter, validetedEmail, consecutiveForEmail, 2, 'email', log, res))) return;

  
  log.info(`finding valid user to send email...`)
  const { valid, error } = await sendTempPasswordResetLink(validetedEmail);

  if (error) {
    if (!(await guard(uniLimiter, compositeKey, consecutiveForCompositeKey, 3, 'ip+email', log, res))) return;
    log.warn(`Email not found`);
  }; 

  if (valid) {
        consecutiveForIp.delete(req.ip!)
        consecutiveForEmail.delete(validetedEmail);
        consecutiveForCompositeKey.delete(compositeKey)
        await resetLimitersUni(compositeKey);
        log.info(`Reset email was send successfully.`)
  };

  } finally {    
    const elapsed = Date.now() - start; 
    const delay = 3000;
    if (elapsed < delay) {
      await waitSomeTime(delay - elapsed, log);
    }
    if (!res.headersSent) {
      res.status(200).json({success: true, details: 'A link to restart your password was sent to your email!'})
      return;
    }
  }
}
