import { Request, Response } from 'express';
import { consumeAndVerifyRefreshToken, revokeRefreshToken, generateRefreshToken } from '../../refreshTokens.js';
import { makeCookie } from '../utils/cookieGenerator.js';
import { generateAccessToken } from '../../accessTokens.js';
import { strangeThings } from "../../anomalies.js";
import { sendTempMfaLink } from '../utils/emailMFA.js';
import { getLogger } from '../utils/logger.js';
import { createHash,randomUUID } from "crypto";
import { guard } from "../utils/limiters/utils/guard.js";
import { getLimiters } from "../utils/limiters/protectedEndpoints/tokensLimiters.js";
import { makeConsecutiveCache } from "../utils/limiters/utils/consecutiveCache.js";
import { getConfiguration } from '../config/configuration.js';
import { EmailMetaDataOTP } from '../types/Emails.js';
import { anomaliesCache } from '~~/utils/anomaliesCache.js';
import { safeAction } from '@riavzon/utils';
import { fakeLogger } from '~~/utils/fakeLogger.js';

const consecutiveForIp = makeConsecutiveCache< {countData:number} >(500, 1000 * 60 * 10);
const consecutiveForCompositeKey = makeConsecutiveCache< {countData:number} >(500, 1000 * 60 * 10);
const consecutiveForRefreshToken = makeConsecutiveCache< {countData:number} >(500, 1000 * 60 * 60 * 12);

/**
 * Rotates both refresh and access tokens on every valid refresh-token use.
 *
 * Flow:
 * - Requires refresh cookie `session` and `canary_id`.
 * - Applies rate limits (by IP, composite key and token hash).
 * - Runs anomaly checks and may trigger an email MFA challenge.
 * - On success, revokes old refresh token, issues new refresh + access, and sets cookies.
 *
 * Responses:
 * - 202: MFA challenge sent via email (no rotation performed yet).
 * - 201: Rotation successful. Returns `{ message, accessToken, accessIat }`.
 * - 401: Login required, re-login required, session expired, or verification failed.
 * - 429: Rate limited by rotation limiters.
 * - 500: Internal errors (DB/server/MFA dispatch).
 *
 * Notes:
 * - Access token `jti` is generated with `randomUUID()`.
 * - Cookies `session` and `iat` are updated on success using strict/same-site settings.
 *
 * @param req Express Request (expects cookies `session` and `canary_id`).
 * @param res Express Response
 */
export const rotateCredentials = async (req: Request, res: Response) => {
  const { jwt } = getConfiguration();
  const { refreshAccessTokenLimiter, refreshTokenLimiter } = getLimiters();
  const rawRefreshToken = req.cookies.session;
  const canary_id = req.cookies.canary_id;
  const log = getLogger().child({service: 'auth', branch: 'strict auth', type: 'rotateCredentials'});


  log.info(`Rotating user's credentials...`)

  if (!canary_id) {
    log.warn(`missing canary_id: ${canary_id}`)
  res.status(401).json({ error: 'Login required' });
  return;
}

  if (!(await guard(refreshAccessTokenLimiter , req.ip!, consecutiveForIp, 1, 'refreshAccessTokenIpLimiter', log, res))) return;
    
  
    try {
      const hashedToken = createHash('sha256').update(rawRefreshToken).digest('hex');

      const anomalies = await safeAction(`${hashedToken}:${canary_id}`, async () => {
        const anon = await strangeThings(rawRefreshToken, canary_id, req.ip!, req.get('User-Agent')!, true);
        return anon;
      }, 5000, fakeLogger)

      const {valid, reason, reqMFA, userId, visitorId} = anomalies;
      const { device: devicePrint, os, browser: browserPrint, city, country, browserType, browserVersion, district,region, regionName, timezone,lat,lon } = req.fingerPrint;

      const location = [country ?? 'Unknown Location', timezone, district, city, region, regionName, lat, lon].filter(Boolean).join('-');
      const device = [ devicePrint ?? 'Unknown Device', os, req.ip].filter(Boolean).join('-');
      const browser = [browserPrint ?? 'Unknown Browser', browserVersion, browserType].filter(Boolean).join('-');
      
      const meta: EmailMetaDataOTP = {
        device,
        browser,
        location
      }


         if (!valid && reqMFA) {
        log.info({token: '[REDACTED]',valid, reason, reqMFA, userId, visitorId},`mfa is triggered`)
        const mfa = await sendTempMfaLink(
          {
          userId: userId!,
          visitor: visitorId!
          }, 
            rawRefreshToken,
            req.ip!,
            res,
            meta
          )
            if (mfa === 'rate_limited') return;
            
            if (!mfa) { 
              log.warn({token: '[REDACTED]',valid, reason, reqMFA, userId, visitorId},`mfa error 500`)
              anomaliesCache()?.delete(hashedToken)
              res.status(500).json({ error: 'Could not send MFA code, try again later' });
              return;
            }
            log.info({token: '[REDACTED]',valid, reason, reqMFA, userId, visitorId},`A login link has been sent to the user`)
            res.status(202).json({ mfa: true, message: 'A login link has been sent to your email.' });
            return;
         }

     if (!valid && !reqMFA) {
       log.info({token: '[REDACTED]',valid, reason, reqMFA, userId, visitorId},`Relogin is required`)
       res.status(401).json({error: 'Re-login is required', message: reason});
       return;
     }


     
      if (!(await guard(refreshTokenLimiter , hashedToken, consecutiveForRefreshToken, 1, 'Refresh Token', log, res))) return;
      
      const compositeKey = `${req.ip}_${hashedToken}`;
      if (!(await guard(refreshAccessTokenLimiter , compositeKey, consecutiveForCompositeKey, 1, 'compositeKey', log, res))) return;

     const safeRotation = await safeAction(`rotate:${hashedToken}`, async () => {
            const result = await consumeAndVerifyRefreshToken(rawRefreshToken);

            if (result.valid && Date.now() - result.sessionTTL!.getTime() >= jwt.refresh_tokens.MAX_SESSION_LIFE) { 
                const revoke = await revokeRefreshToken(rawRefreshToken);

                if (!revoke.success) {
                    log.error(`DB error revoking token`)
                    return {
                      status: 500,
                      error: 'Server error',
                      action: "SERVER_ERROR"
                    }
                } else {
                    log.info({user: result.userId},`User's Session is expired`);
                    return {
                      status: 401,
                      error: 'Session is expired',
                      action: 'CLEAR_COOKIES'
                    }
                }
            } 

            if (!result.valid) {
                  log.warn(`Error verifying credentials ${result.reason}`)
                  return {
                    status: 401,
                    error: "Invalid session",
                    action: 'REJECT'
                  }
            };
           log.info(`Verifying credentials succeeded, revoking...`)
           const revoke = await revokeRefreshToken(rawRefreshToken);
           if (!revoke.success) {
              log.error(`DB error revoking token`)
                return {
                  status: 500,
                  error: 'Server error',
                  action: "SERVER_ERROR"
                }
           }

          const newRefresh = await generateRefreshToken(
              jwt.refresh_tokens.refresh_ttl,
              result.userId!,
              result.sessionTTL ? result.sessionTTL : undefined
            );

          const newAccess  = generateAccessToken({
              id: result.userId!,
              visitor_id: result.visitor_id!,
              jti: randomUUID()
            });
          return {
              status: 201,
              action: 'ROTATE',
              data: {
                  accessToken: newAccess,
                  newRefreshRaw: newRefresh.raw,
                  expiresAt: newRefresh.expiresAt
              }
          };

     }, 5000, log)

    if (safeRotation.action === "SERVER_ERROR") {
        res.status(500).json({ error: safeRotation.error });
        return;
    }
    if (safeRotation.action === 'CLEAR_COOKIES') {
      res.clearCookie('session', {
             httpOnly: true,
             sameSite: "strict", 
             secure: true,
             domain: jwt.refresh_tokens.domain,
             path: '/'
        });
      res.clearCookie('iat', {
             httpOnly: true,
             sameSite: "strict", 
             secure: true,
             domain: jwt.refresh_tokens.domain,
             path: '/'
      });
      res.status(safeRotation.status).json({error: safeRotation.error})
      return;
    }

    if(safeRotation.action === 'REJECT') {
        res.status(safeRotation.status).json({ error: safeRotation.error })
        return;
    }

    if (safeRotation.action === "ROTATE") {
        const { data } = safeRotation;
         if (!data) throw new Error('UNEXPECTED_ERROR');

          makeCookie(res, 'iat', Date.now().toString(), {
            httpOnly: true,
            secure:   true,
            sameSite: 'strict',
            path:     '/',
            expires:  data.expiresAt
          });

        makeCookie(res, 'session', data.newRefreshRaw, {
            httpOnly: true,
            sameSite: 'strict',
            secure:   true,
            domain:   jwt.refresh_tokens.domain,
            path:     '/',
            expires:  data.expiresAt
        });
          await refreshTokenLimiter.block(hashedToken, 60 * 60 * 24 * 3);
          await refreshAccessTokenLimiter.block(compositeKey, 60 * 60 * 24 * 3);

          log.info(`Refresh & access tokens rotated successfully`);
          res.status(201).json({
            message:  'Refresh & access tokens rotated',
            accessToken: data.accessToken,
            accessIat: Date.now().toString()
          }) 
          return;
    }

    return;
    
  } catch (err) {
    log.error({err},`Failed rotating user's credentials`)
     res.status(500).json({ error: 'Server error rotating refresh token' })
    return;
  }
};
