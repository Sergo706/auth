import { verifyTempJwtLink } from "../../tempLinks.js";
import { Request, Response, NextFunction } from "express";
import { getLogger } from "../utils/logger.js";
import { getUniLimiter, resetLimitersUni } from "../utils/limiters/protectedEndpoints/linkVerificationLimiter.js";
import { guard } from "../utils/limiters/utils/guard.js";
import { makeConsecutiveCache } from "../utils/limiters/utils/consecutiveCache.js";
import { getLimiters } from "../utils/limiters/protectedEndpoints/tempPostRoutesLimiter.js";
import { magicLinksCache } from "../utils/magicLinksCache.js";
const consecutiveForIpPassword = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 30);
const consecutiveForIpMfa = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 30);
const usageCountPost = makeConsecutiveCache<{count:number}>(1000, 1000 * 60 * 20);
const usageCountGet = makeConsecutiveCache<{count:number}>(1000, 1000 * 60 * 20);

const allowedPerSuccessfulGet = 5;
const allowedPerSuccessfulPost = 1;

/**
 * Verify MFA magic links (GET to preview, POST to consume) with rate limiting.
 *
 * Query: `?temp=<token>` and route param `:visitor` must match token payload.
 *
 * - GET: allows up to a limited number of previews; responds 200 when valid.
 * - POST: allows a single use; on success calls `next()` to continue the flow.
 *
 * Errors: 400 for invalid/expired/mismatched links; rate limits applied.
 */
export const linkMfaVerification = async (req: Request, res: Response, next: NextFunction) => {
const log = getLogger().child({service: 'auth', branch: `tempLinks`, linkType: 'mfa'})
const { usedJtiLimiter } = getLimiters();
const token = req.query.temp;

if (typeof token !== 'string') {
    log.warn('invalid token type');
    res.status(400).json({error: 'invalid token type'});
    return;
}

log.info({ method: req.method }, 'Verifying link...')


if (!(await guard(getUniLimiter(), req.ip!, consecutiveForIpMfa, 1, 'ip', log, res))) return;

if (!token) {
    log.warn('Link not provided');
    res.status(400).json({error: 'Link not provided'});
    return;
}

const results = verifyTempJwtLink(token);

if (!results.valid || !results.payload) {
    log.warn({details: results.errorType},'Link is not valid or expired');
    res.status(400).json({error: 'Link is not valid or expired', details: results.errorType});
    return;
}

if (Number(req.params.visitor) !== results.payload.visitor) {
  log.warn('Invalid link URL');
   res.status(400).json({ error: 'Invalid link URL' });
  return;
}
    const raw = results.payload;
    
  if (typeof raw.visitor !== 'number') {
    log.warn('Malformed token payload');
     res.status(401).json({ error: 'Malformed token payload' })
     return;
  }
    req.link = {     
      visitor: raw.visitor,  
      subject: raw.subject,
      purpose: raw.purpose,
      jti: raw.jti
    };

    const isUsed = await usedJtiLimiter.get(req.link.jti!);
    if (isUsed !== null &&  isUsed.consumedPoints > 0 && isUsed.remainingPoints === 0) {
      log.warn({userDetail: req.link},'User tried to use a temp link again');
      magicLinksCache().delete(token);
      res.status(400).json({ error: 'Link is not valid or expired' });
      return 
    }

   if (req.method === 'GET') {
     const getEntry = (usageCountGet.get(req.link.jti!)?.count ?? 0) + 1;
     usageCountGet.set(req.link.jti!, { count: getEntry });
     log.info({count: getEntry, out_of: allowedPerSuccessfulGet},'User hit a mfa link, with a get req.');

      if (getEntry > allowedPerSuccessfulGet) {
        log.warn({count: getEntry, out_of: allowedPerSuccessfulGet},'User hit an expired mfa link with a get method');
        res.status(400).json({error: 'This link can only be used once'})
        return;
      };

    log.info('link verified');
     consecutiveForIpMfa.delete(req.ip!);
     await resetLimitersUni(req.ip!)
     res.status(200).json({link: 'MFA Code'});
    return;  
  }

  const postEntry = (usageCountPost.get(req.link.jti!)?.count ?? 0) + 1;
  usageCountPost.set(req.link.jti!, { count: postEntry });
  log.info({count: postEntry, out_of: allowedPerSuccessfulPost},'User hit an mfa link, with a post req.');

   if (postEntry > allowedPerSuccessfulPost) {
     log.warn({count: postEntry, out_of: allowedPerSuccessfulGet},'User hit an expired mfa link with a post method');
     res.status(400).json({error: 'This link can only be used once'})
     return;
   };

  return next();
} 


/**
 * Verify password-reset magic links (GET to preview, POST to consume) with rate limiting.
 *
 * Query: `?temp=<token>` and route param `:visitor` must match token payload.
 *
 * - GET: allows a limited number of previews; responds 200 when valid.
 * - POST: allows a single consumption; on success calls `next()`.
 *
 * Errors: 400 for invalid/expired/mismatched links; rate limits applied.
 */
export const linkPasswordVerification = async (req: Request, res: Response, next: NextFunction) => {
const log = getLogger().child({service: 'auth', branch: `tempLinks`, linkType: 'password-reset'})
const { usedJtiLimiter } = getLimiters();
const token = req.query.temp;

if (typeof token !== 'string') {
    log.warn('invalid token type');
    res.status(400).json({error: 'invalid token type'});
    return;
}

log.info('Verifying link...')


if (!(await guard(getUniLimiter(), req.ip!, consecutiveForIpPassword, 1, 'ip', log, res))) return;

if (!token) {
  log.warn('Link not provided');
    res.status(400).json({error: 'Link not provided'});
    return;
}

const results = verifyTempJwtLink(token);


if (!results.valid || !results.payload) {
  log.warn({details: results.errorType},'Link is not valid or expired');
    res.status(400).json({error: 'Link is not valid or expired'});
    return;
}

if (Number(req.params.visitor) !== results.payload.visitor) {
  log.warn('Invalid link URL');
   res.status(400).json({ error: 'Invalid link URL' });
  return;
}
    const raw = results.payload;
    
  if (typeof raw.visitor !== 'number') {
    log.warn('Malformed token payload');
     res.status(401).json({ error: 'Malformed token payload' })
     return;
  }
    req.link = {        
      visitor: raw.visitor,  
      subject: raw.subject,
      purpose: raw.purpose,
      jti: raw.jti
    };

    const isUsed = await usedJtiLimiter.get(req.link.jti!);
    if (isUsed !== null &&  isUsed.consumedPoints > 0 && isUsed.remainingPoints === 0) {
      log.warn({userDetail: req.link},'User tried to use a temp link again');
      magicLinksCache().delete(token);
      res.status(400).json({ error: 'Link is not valid or expired' });
      return 
    }

   if (req.method === 'GET') {

     const getEntry = (usageCountGet.get(req.link.jti!)?.count ?? 0) + 1;
     usageCountGet.set(req.link.jti!, { count: getEntry });
     log.info({count: getEntry, out_of: allowedPerSuccessfulGet},'User hit a password reset link, with a get req.');

      if (getEntry > allowedPerSuccessfulGet) {
        log.warn({count: getEntry, out_of: allowedPerSuccessfulGet},'User hit an expired password link with a get method');
        res.status(400).json({error: 'This link can only be used once'})
        return;
      };

      log.info('link verified')
      consecutiveForIpPassword.delete(req.ip!);
      await resetLimitersUni(req.ip!)
     res.status(200).json({link: 'Password Reset'});
    return;  
  }

  const postEntry = (usageCountPost.get(req.link.jti!)?.count ?? 0) + 1;
  usageCountPost.set(req.link.jti!, { count: postEntry });
  log.info({count: postEntry, out_of: allowedPerSuccessfulPost},'User hit a password reset link, with a post req.');

   if (postEntry > allowedPerSuccessfulPost) {
     log.warn({count: postEntry, out_of: allowedPerSuccessfulPost},'User hit an expired password link with a post method');
     res.status(400).json({error: 'This link can only be used once'})
     return;
   };

  return next();
} 
