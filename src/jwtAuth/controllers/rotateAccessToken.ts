import { Request, Response } from "express";
import { revokeRefreshToken, verifyRefreshToken } from "../../refreshTokens.js";
import { generateAccessToken } from "../../accessTokens.js";
import { strangeThings } from "../../anomalies.js";
import { sendTempMfaLink } from "../utils/emailMFA.js";
import { getLogger } from "../utils/logger.js";
import { createHash, randomUUID } from "crypto";
import { guard } from "../utils/limiters/utils/guard.js";
import { getLimiters} from "../utils/limiters/protectedEndpoints/tokensLimiters.js";
import { makeConsecutiveCache } from "../utils/limiters/utils/consecutiveCache.js";
import { resetLimiters } from "../utils/limiters/utils/resetLimiters.js";
import { getConfiguration } from "../config/configuration.js";

const consecutiveForIp = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 10);
const consecutiveForCompositeKey = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 10);
const consecutiveForRefreshToken = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 60 * 12);

/**
 * Rotates the access token using a valid refresh token cookie.
 *
 * Behavior:
 * - Requires refresh cookie `session` and `canary_id`.
 * - Applies rate limits (by IP, composite key and token hash).
 * - Verifies anomalies and may trigger MFA (no rotation when MFA is required).
 * - On success, returns a new access token with a fresh `jti` (via `randomUUID()`).
 * - If the refresh session reached maximum life, clears cookies and asks re-login.
 *
 * Responses:
 * - 200: Access token rotated. Returns `{ accessToken, accessIat }`.
 * - 202: MFA challenge sent via email.
 * - 401: Login required, re-login required, session expired, or verification failed.
 * - 429: Rate limited by rotation limiters.
 * - 500: Internal errors (DB/server/MFA dispatch).
 *
 * @param req Express Request (expects cookies `session` and `canary_id`).
 * @param res Express Response
 */
export const rotateAccessToken =  async (req: Request, res: Response) => {
        const { jwt } = getConfiguration();

        const rawRefreshToken = req.cookies.session;
        const canary_id = req.cookies.canary_id;
        const log = getLogger().child({service: 'auth', branch: 'access token', type: 'rotateAccessToken'})
        const { refreshAccessTokenLimiter, refreshTokenLimiter } = getLimiters();
        log.info('Rotating access token...')

      if (!canary_id) {
        log.warn({canary_id},'missing canary_id')
        res.status(401).json({ error: 'Login required' });
        return;
        }

    if (!(await guard(refreshAccessTokenLimiter, req.ip!, consecutiveForIp, 1, 'refreshAccessTokenIpLimiter', log, res))) return;

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
        if (!(await guard(refreshAccessTokenLimiter, compositeKey, consecutiveForCompositeKey, 1, 'compositeKey', log, res))) return;

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
             res.status(401).json({session: 'Session is expired'})
             return;
          }

         if (!result.valid) {
           log.warn(`refresh token is not valid: ${result.reason}`)
            res.status(401).json({error: result.reason})
            return;
         }

         const accessToken = generateAccessToken({
            id: result.userId!,
            visitor_id: result.visitor_id!,
            jti: randomUUID()
        });

        resetLimiters(log, hashedToken, [refreshTokenLimiter]);
        consecutiveForRefreshToken.delete(hashedToken);
        log.info({userId: result.userId, visitorId: result.visitor_id},`access token rotated successfully`)
        res.status(200).json({ accessToken: accessToken, accessIat: Date.now().toString() });
        return;

      } catch(err) {
        log.error({err},`Error Rotating access token`)
          res.status(500).json({error: `Error Rotating access token: ${err}`})
       }
    };
