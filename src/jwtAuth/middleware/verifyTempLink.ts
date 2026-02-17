import { verifyTempJwtLink } from "../../tempLinks.js";
import { Request, Response, NextFunction } from "express";
import { getLogger } from "../utils/logger.js";
import { getUniLimiter, resetLimitersUni } from "../utils/limiters/protectedEndpoints/linkVerificationLimiter.js";
import { guard } from "../utils/limiters/utils/guard.js";
import { makeConsecutiveCache } from "../utils/limiters/utils/consecutiveCache.js";
import { getLimiters } from "../utils/limiters/protectedEndpoints/tempPostRoutesLimiter.js";
import { magicLinksCache } from "../utils/magicLinksCache.js";
import { validateSchema } from '../utils/validateZodSchema.js';
import { verificationLink, type VerificationLinkSchema } from "../types/CustomMfaSchema.js";
import { toDigestHex } from "../utils/hashChecker.js";
import crypto from "node:crypto"
import { getConfiguration } from "../config/configuration.js";
import { buildInMfaFlows, type BuildInMfaFlowsSchema } from "../types/MfaAndPasswordResetSchema.js";
const consecutiveForIpPassword = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 30);
const consecutiveForIpMfa = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 30);
const consecutiveForIpCustomMfa = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 30);
const usageCountPost = makeConsecutiveCache<{count:number}>(1000, 1000 * 60 * 20);
const usageCountGet = makeConsecutiveCache<{count:number}>(1000, 1000 * 60 * 20);



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
const { magic_links } = getConfiguration()
const { allowedPerSuccessfulGet, allowedPerSuccessfulPost } = magic_links.thresholds.adaptiveMfa
const data = req.query as unknown as BuildInMfaFlowsSchema;
const result = await validateSchema(buildInMfaFlows, data, req, log)

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

const { token, random, reason, visitor } = result.data;


log.info({ method: req.method }, 'Verifying link...')


if (!(await guard(getUniLimiter(), req.ip!, consecutiveForIpMfa, 1, 'ip', log, res))) return;

const results = verifyTempJwtLink<{ randomHashed: string }>(token);

if (!results.valid || !results.payload) {
    log.warn({details: results.errorType},'Link is not valid or expired');
    res.status(400).json({error: 'Link is not valid or expired', details: results.errorType});
    return;
}

if (visitor !== results.payload.visitor) {
  log.warn('Invalid link URL');
   res.status(400).json({ error: 'Invalid link URL' });
  return;
}
    const raw = results.payload;
    const { input: providedRandom } = await toDigestHex(random)
    const signedProvidedRandom = Buffer.from(providedRandom, 'hex')
    const signedRandom = Buffer.from(raw.randomHashed, 'hex');
  
  if (typeof raw.visitor !== 'number' || 
       raw.purpose !== reason || 
       raw.subject !== `${reason}_${visitor}` ||
       signedProvidedRandom.length !== signedRandom.length 
      ) {
     log.warn('Malformed token payload');
     res.status(401).json({ 
      ok: false,
      date: new Date().toISOString(), 
      reason: 'Malformed token payload' 
    })
     return;
  }


  if (!crypto.timingSafeEqual(signedProvidedRandom, signedRandom)) {
    log.warn('Malformed token payload: hash mismatch');
    res.status(401).json({ 
      ok: false,
      date: new Date().toISOString(), 
      reason: 'Malformed token payload' 
     })
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
     res.status(200).json({      
      ok: true,
      date: new Date().toISOString(), 
      data: {
        link: 'MFA Code',
        reason: raw.purpose 
      }});
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
const { magic_links } = getConfiguration()
const { allowedPerSuccessfulGet, allowedPerSuccessfulPost } = magic_links.thresholds.linkPasswordVerification;


const data = req.query as unknown as BuildInMfaFlowsSchema;
const result = await validateSchema(buildInMfaFlows, data, req, log)

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

const { token, random, reason, visitor } = result.data;


log.info('Verifying link...')


if (!(await guard(getUniLimiter(), req.ip!, consecutiveForIpPassword, 1, 'ip', log, res))) return;


const results = verifyTempJwtLink<{ randomHashed: string }>(token);


if (!results.valid || !results.payload) {
  log.warn({details: results.errorType},'Link is not valid or expired');
    res.status(400).json({error: 'Link is not valid or expired'});
    return;
}

if (visitor !== results.payload.visitor) {
  log.warn('Invalid link URL');
   res.status(400).json({ error: 'Invalid link URL' });
  return;
}
    const raw = results.payload;
    const { input: providedRandom } = await toDigestHex(random)
    const signedProvidedRandom = Buffer.from(providedRandom, 'hex')
    const signedRandom = Buffer.from(raw.randomHashed, 'hex');
  
  if (typeof raw.visitor !== 'number' || 
       raw.purpose !== reason || 
       raw.subject !== `${reason}_${visitor}` ||
       signedProvidedRandom.length !== signedRandom.length 
      ) {
     log.warn('Malformed token payload');
     res.status(401).json({ 
      ok: false,
      date: new Date().toISOString(), 
      reason: 'Malformed token payload' 
    })
     return;
  }


  if (!crypto.timingSafeEqual(signedProvidedRandom, signedRandom)) {
    log.warn('Malformed token payload: hash mismatch');
    res.status(401).json({ 
      ok: false,
      date: new Date().toISOString(), 
      reason: 'Malformed token payload' 
     })
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
      res.status(200).json({      
      ok: true,
      date: new Date().toISOString(), 
      data: {
        link: 'Password Reset',
        reason: raw.purpose 
      }});
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
/**
 * Middleware for verifying custom Multi-Factor Authentication (MFA) magic links.
 * 
 * @description
 * This middleware validates the temporary magic link used in custom MFA flows:
 * 1. **Schema Validation**: Validates `token`, `random`, `reason` (query) and `visitor` (params) using Zod.
 * 2. **Global Rate Limiting**: Uses `linkVerificationLimiter` to prevent brute-forcing.
 * 3. **JWT Verification**: Verifies the signature and payload of the `temp` token.
 * 4. **Random Hash Check**: Cryptographically compares the provided `random` string with the `randomHashed` stored in the JWT using `timingSafeEqual`.
 * 5. **Payload integrity**: Ensures `visitor`, `purpose`, and `subject` match the request context.
 * 6. **Single Use enforcement**: Prevents replay attacks by checking a JTI-based limiter and `magicLinksCache`.
 * 
 * On success, populates `req.link` and calls `next()`.
 * 
 * @param {Request} req - Express request object.
 * @param {Response} res - Express response object.
 * @param {NextFunction} next - Express next function.
 * 
 * @returns {Promise<void>}
 * 
 * @example
 * // Used in magicLinks.ts routes
 * router.route("/auth/verify-custom-mfa")
 *   .post(customMfaFlowsVerification, verifyCustomMfa);
 */
export const customMfaFlowsVerification = async (req: Request, res: Response, next: NextFunction) => {
  const log = getLogger().child({service: 'auth', branch: `tempLinks`, linkType: 'custom-mfa'})
  const { usedJtiLimiter } = getLimiters();
  const { magic_links } = getConfiguration()
  const { allowedPerSuccessfulGet, allowedPerSuccessfulPost } = magic_links.thresholds.customMfaFlowsAndEmailChanges
  const data = req.query as unknown as VerificationLinkSchema;
  const result = await validateSchema(verificationLink, data, req, log)

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

  log.info({ method: req.method }, 'Verifying link...')

  if (!(await guard(getUniLimiter(), req.ip!, consecutiveForIpCustomMfa, 1, 'ip', log, res))) return;

  const { token, random, reason, visitor } = result.data;

  const results = verifyTempJwtLink<{ randomHashed: string }>(token);

  if (!results.valid || !results.payload) {
      log.warn({details: results.errorType},'Link is not valid or expired');
      res.status(400).json({error: 'Link is not valid or expired', details: results.errorType});
      return;
  }

  if (visitor !== results.payload.visitor) {
    log.warn('Invalid link URL');
    res.status(400).json({ 
      ok: false,
      date: new Date().toISOString(), 
      reason: 'Invalid link URL'
     });
    return;
  }

  const raw = results.payload;
  const { input: providedRandom } = await toDigestHex(random)
  const signedProvidedRandom = Buffer.from(providedRandom, 'hex')
  const signedRandom = Buffer.from(raw.randomHashed, 'hex');
  
  if (typeof raw.visitor !== 'number' || 
       raw.purpose !== reason || 
       raw.subject !== `${reason}_${visitor}` ||
       signedProvidedRandom.length !== signedRandom.length 
      ) {
     log.warn('Malformed token payload');
     res.status(401).json({ 
      ok: false,
      date: new Date().toISOString(), 
      reason: 'Malformed token payload' 
    })
     return;
  }


  if (!crypto.timingSafeEqual(signedProvidedRandom, signedRandom)) {
    log.warn('Malformed token payload: hash mismatch');
    res.status(401).json({ 
      ok: false,
      date: new Date().toISOString(), 
      reason: 'Malformed token payload' 
     })
    return;
  }

  req.link = {     
      visitor: raw.visitor,  
      subject: raw.subject,
      purpose: raw.purpose,
      jti: raw.jti,
    }; 

    const isUsed = await usedJtiLimiter.get(req.link.jti!);
    if (isUsed !== null && isUsed.consumedPoints > 0 && isUsed.remainingPoints === 0) {
      log.warn({userDetail: req.link},'User tried to use a temp link again');
      magicLinksCache().delete(token);
      res.status(400).json({ 
        ok: false,
        date: new Date().toISOString(), 
        reason: 'Link is not valid or expired'
      });
      return 
    }

   if (req.method === 'GET') {
     const getEntry = (usageCountGet.get(req.link.jti!)?.count ?? 0) + 1;
     usageCountGet.set(req.link.jti!, { count: getEntry });
     log.info({count: getEntry, out_of: allowedPerSuccessfulGet},'User hit a custom mfa link, with a get req.');

      if (getEntry > allowedPerSuccessfulGet) {
        log.warn({count: getEntry, out_of: allowedPerSuccessfulGet},'User hit an expired custom mfa link with a get method');
        res.status(400).json({
          ok: false,
          date: new Date().toISOString(), 
          reason: 'This link can only be used once'
        })
        return;
      };

    log.info('link verified');
     consecutiveForIpCustomMfa.delete(req.ip!);
     await resetLimitersUni(req.ip!)
     res.status(200).json({ 
      ok: true,
      date: new Date().toISOString(), 
      data: {
        link: 'Custom MFA',
        reason: raw.purpose 
      }
    });
    return;  
  }

  const postEntry = (usageCountPost.get(req.link.jti!)?.count ?? 0) + 1;
  usageCountPost.set(req.link.jti!, { count: postEntry });
  log.info({count: postEntry, out_of: allowedPerSuccessfulPost},'User hit a custom mfa link, with a post req.');

   if (postEntry > allowedPerSuccessfulPost) {
     log.warn({count: postEntry, out_of: allowedPerSuccessfulPost},'User hit an expired custom mfa link with a post method');
     res.status(400).json({
          ok: false,
          date: new Date().toISOString(), 
          reason: 'This link can only be used once'
     })
     return;
   };

  return next();
}