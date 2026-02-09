import { getLogger } from "../utils/logger.js";
import { verifyAccessToken } from "../../accessTokens.js";
import { Request, Response, NextFunction } from "express";
import { strangeThings } from "../../anomalies.js";
import { sendTempMfaLink } from "../utils/emailMFA.js";
import { getLimiters } from '../utils/limiters/protectedEndpoints/tokensLimiters.js'
import { makeConsecutiveCache } from "../utils/limiters/utils/consecutiveCache.js";
import { guard } from "../utils/limiters/utils/guard.js";
import { EmailMetaDataOTP } from "../types/Emails.js";

const consecutiveForJti = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 60 * 24);

/**
 * Verifies the access token and refresh cookies, runs anomaly checks,
 * and enriches `req.user` with identity, roles, and the decoded payload.
 *
 * Requirements:
 * - `req.token` must contain a Bearer access token.
 * - Refresh cookies `session` and `canary_id` must be present.
 * - Access token must be valid and not blacklisted by the limiter.
 *
 * On success attaches:
 * ```ts
 * req.user = {
 *   userId,
 *   visitor_id,
 *   accessTokenId,
 *   roles: string[],
 *   payload: JwtPayload
 * }
 * ```
 *
 * Responses:
 * - 202: MFA challenge sent via email.
 * - 401: Missing/invalid token, missing refresh cookies, malformed payload, or verification failed.
 * - 500: Internal errors (MFA dispatch or verification flow).
 */
export const protectRoute = async (req: Request, res: Response, next: NextFunction) => {
 const token = req.token;
 const session = req.cookies.session;
 const canary = req.cookies.canary_id;
const { blackList } = getLimiters();
  const log = getLogger().child({service: 'auth', branch: 'access token', type: 'protectRoute'})
    log.info(`verifying access token...`);

    if (!token){
    log.warn(`access token don't provided or header malformed`)
    res.status(401).json({ error: 'access token don`t provided or header malformed'});
    return;
    }
    
    if (!session || !canary) {
    log.warn('Refresh cookies missing');
     res.status(401).json({ error: 'Login required' });
     return;
  }
    
    const result = verifyAccessToken(token);
   
   if (!result.valid || !result.payload) {
    log.warn({error: result.errorType},`access token verification failed`)
    res.status(401).json({ error: result.errorType});
    return;
  }

  const raw = result.payload;

  if (Number.isNaN(Number(result.payload.sub)) || typeof raw.visitor !== 'number') {
    log.warn(`Malformed token payload`)
    res.status(401).json({ error: 'Malformed token payload' })
    return;
  }
     if (!(await guard(blackList, result.payload.jti!, consecutiveForJti, 2, 'access token blacklist', log, res))) return;
  
      const {valid, reason, reqMFA, userId, visitorId} = await
    strangeThings(session, canary, req.ip!, req.get('User-Agent')!, false);
    
      const { device, os, browser, city, country, browserType} = req.fingerPrint;
      const meta: EmailMetaDataOTP = {
            device: `${device ?? 'Unknown Device'}-${os ?? ''}-${req.ip!}`.trim(),
            browser: `${browser ?? 'Unknown Browser'}-${browserType ?? ''}`.trim(),
            location: `${country ?? 'Unknown Location'}-${city ?? ''}`.trim()
      }

      if (!valid && reqMFA) {
        log.info({token: '[REDACTED]',valid, reason, reqMFA, userId, visitorId},`mfa is triggered`)
        const mfa = await sendTempMfaLink(
          {
          userId: userId!,
          visitor: visitorId!
          }, 
            session,
            req.ip!,
            res,
            meta
          )
            if (mfa === 'rate_limited') return;
            
            if (!mfa) { 
              log.warn({token: '[REDACTED]',valid, reason, reqMFA, userId, visitorId},`mfa error 500`)
            res.status(500).json({ error: 'Could not send MFA code, try again later' });
            return;
            }
            log.info({token: '[REDACTED]',valid, reason, reqMFA, userId, visitorId},`A login link has been sent to the user`)
            res.status(202).json({ mfa: true, message: 'A login link has been sent to your email.' });
            return;
         }

     if (!valid && !reqMFA) {
       log.info({token: '[REDACTED]',valid, reason, reqMFA, userId, visitorId},`Relogin is required`)
       res.status(401).json({error: 'Relogin is required', reason: reason});
       return;
     }

   log.info('Access token + anomaly checks passed');
    req.user = {
      userId: result.payload.sub,         
      visitor_id: result.payload.visitor,
      accessTokenId: result.payload.jti,  
      roles: result.payload.roles ?? [],
      payload: result.payload
    };
 next();
}   
