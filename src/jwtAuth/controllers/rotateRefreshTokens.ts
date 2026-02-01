import { Request, Response } from "express";
import { verifyRefreshToken, generateRefreshToken, revokeRefreshToken } from "../../refreshTokens.js";
import { makeCookie } from "../utils/cookieGenerator.js";
import { strangeThings } from "../../anomalies.js";
import { sendTempMfaLink } from "../utils/emailMFA.js";
import { getLogger } from "../utils/logger.js";
import { rotateInPlaceRefreshToken } from "../utils/rotateRefreshTokens.js";
import { createHash } from "crypto";
import { guard } from "../utils/limiters/utils/guard.js";
import { getLimiters } from "../utils/limiters/protectedEndpoints/tokensLimiters.js";
import { makeConsecutiveCache } from "../utils/limiters/utils/consecutiveCache.js";
import { getConfiguration } from "../config/configuration.js";


const consecutiveForIp = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 60 * 12);
const consecutiveForCompositeKey = makeConsecutiveCache< {countData:number} >(2000, 60 * 60 * 12);
const consecutiveForRefreshToken = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 60 * 12);

/**
 * Rotate refresh credentials when nearing expiry or when the refresh token has
 * expired but the overall session is still within `MAX_SESSION_LIFE`.
 *
 * Flow:
 * - Enforce canary cookie, rate limits, and anomaly checks (`strangeThings`).
 * - If session exceeds `MAX_SESSION_LIFE`, revoke and clear cookies (401).
 * - If token is valid and fresh, respond 200 without changes.
 * - If token is expired but eligible, rotate (in-place helper or new issuance),
 *   set new cookies, and respond 201.
 *
 * Responses: 200 (up to date), 201 (rotated), 401 (relogin/MFA), 500 (server).
 */
export const rotateRefreshTokens = async (req: Request, res: Response) => { 
        const { jwt } = getConfiguration();
        const rawRefreshToken = req.cookies.session;
        const canary_id = req.cookies.canary_id;
        const log = getLogger().child({service: 'auth', branch: 'refresh tokens', type: 'rotateRefreshTokens'})
        const { refreshTokenLimiterUnion, refreshTokenLimiter } = getLimiters();
        log.info(`Refreshing token...`)

      if (!canary_id) {
      log.warn(`missing canary_id: ${canary_id}`)
      res.status(401).json({ error: 'Login required' });
      return;
    }

     if (!(await guard(refreshTokenLimiterUnion, req.ip!, consecutiveForIp, 1, 'refreshTokenLimiterUnion', log, res))) return;
    
        try { 
      const {valid, reason, reqMFA, userId, visitorId} = 
      await strangeThings(rawRefreshToken, canary_id, req.ip!, req.get('User-Agent')!, false);

         if (!valid && reqMFA) {
          log.info({token: '[REDACTED]',valid, reason, reqMFA, userId, visitorId},`mfa is triggered`)
        const mfa = await sendTempMfaLink(
          {
          userId: userId!,
          visitor: visitorId!
          }, 
            rawRefreshToken,
            req.ip!,
            res
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
         
        const hashedToken = createHash('sha256').update(rawRefreshToken).digest('hex');
       
        if (!(await guard(refreshTokenLimiter, hashedToken, consecutiveForRefreshToken, 1, 'Refresh Token', log, res))) return;

        const compositeKey = `${req.ip}_${hashedToken}`;
        if (!(await guard(refreshTokenLimiterUnion , compositeKey, consecutiveForCompositeKey, 1, 
          'refreshTokenLimiterUnion compositeKey', log, res))) return;


         const result = await verifyRefreshToken(rawRefreshToken);       
      
         if (result.valid && Date.now() - result.sessionStartedAt!.getTime() >= jwt.refresh_tokens.MAX_SESSION_LIFE) {
          const revoke = await revokeRefreshToken(rawRefreshToken);
              if (!revoke.success) {
                  log.error(`DB error revoking token`)
                  res.status(500).json({ error: 'DB error revoking token' });
                  return;
              }
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
            log.info({user: result.userId},`User's Session is expired`);
            res.status(401).json({error: 'Session is expired'})
            return;
         }

         if (result.valid) {
            log.info({userID: result.userId, visitorId: result.visitor_id},`Refresh is up to date`)
            res.status(200).json({session: 'Refresh is up to date', userID: result.userId})
            return;
         }

        if (!result.valid && result.reason === 'Token not found') {
          log.info({userID: result.userId, visitorId: result.visitor_id},`Token not found`)
          res.status(401).json({error: 'Token not found'})
          return;
         }

         if (!result.valid && result.reason === 'Token has been revoked') {
          log.info({userID: result.userId, visitorId: result.visitor_id},`Token has been revoked`)
          res.status(401).json({error: 'Token has been revoked, please login again'});
          return;
         }
   
        if (!result.valid && result.reason === 'Token expired') {
            log.info({userID: result.userId, visitorId: result.visitor_id},`Token expired, Making a new one...`)

         if (typeof result.userId !== 'number') {
          log.info({userID: result.userId, visitorId: result.visitor_id},`Missing user ID on expired token`)
            res.status(500).json({ error: 'Missing user ID on expired token' });
            return; 
           }

           log.info({userID: result.userId, visitorId: result.visitor_id},`Refresh verified...`)
           const updateToken = await rotateInPlaceRefreshToken(jwt.refresh_tokens.refresh_ttl, result.userId, rawRefreshToken);
           log.info({userID: result.userId, visitorId: result.visitor_id},`Rotating token...`)

           let newTokenValue; 
           let expiresAt;
          
           if (updateToken.rotated) {
            log.info({userID: result.userId, visitorId: result.visitor_id},`token rotated`)
              newTokenValue = updateToken.raw;
              expiresAt    = updateToken.expiresAt;
           } else {
            log.info({userID: result.userId, visitorId: result.visitor_id},`Token can't be rotated, generating new one...`)
           const newSession = await generateRefreshToken(jwt.refresh_tokens.refresh_ttl, result.userId);
              newTokenValue = newSession.raw;
              expiresAt     = newSession.expiresAt;
           }
            makeCookie(res, 'iat', Date.now().toString(), {
                httpOnly: true,
                secure:   true,
                sameSite: 'strict',
                path:     '/',
                expires: expiresAt,
                });
            makeCookie(res, 'session', newTokenValue!, {
               httpOnly: true,
               sameSite: "strict", 
               expires: expiresAt,
               secure: true,
               domain: jwt.refresh_tokens.domain,
              path: '/'
            })
            log.info({userID: result.userId, visitorId: result.visitor_id},`Refresh Token was expired and now is up to date`)
           res.status(201).json({session: 'Refresh Token was expired and now is up to date', userID: result.userId})
          return;
        }
         if (!result.valid && result.reason === 'Unexpected Error') {
           log.info({userID: result.userId, visitorId: result.visitor_id},`Server error validating refresh token`)
            res.status(500).json({ error: 'Server error validating refresh token' });
            return;
         } else { 
          log.fatal({userID: result.userId, visitorId: result.visitor_id},`Unexpected results Cannot rotate refresh token`)
          res.status(500).json({ error: 'Unexpected results Cannot rotate refresh token' });  
          return;
        }
         } catch(err) {
           log.error({err},`Error Rotating refresh token`)
            console.warn(`Error Rotating refresh token: ${err}`)
            res.status(500).json({error: `Error Rotating refresh token: ${err}`})
            return;
         }
       }
