import { Request, Response } from "express";
import { revokeRefreshToken, verifyRefreshToken } from "../../refreshTokens.js";
import { generateAccessToken } from "../../accsessTokens.js";
import { strangeThings } from "../../anomalies.js";
import { sendTempMfaLink } from "../utils/emailMFA.js";
import { logger } from "../utils/logger.js";
import { config } from "../config/secret.js";
import { createHash } from "crypto";
import { guard } from "../utils/limiters/utils/guard.js";
import { refreshAccessTokenLimiter, blackList, refreshTokenLimiter } from "../utils/limiters/protectedEndpoints/tokensLimiters.js";
import { makeConsecutiveCache } from "../utils/limiters/utils/consecutiveCache.js";
import { resetLimiters } from "../utils/limiters/utils/resetLimiters.js";


const consecutiveForIp = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 10);
const consecutiveForCompositeKey = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 10);
const consecutiveForRefreshToken = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 60 * 12);

export const rotateAccessToken =  async (req: Request, res: Response) => {
        const rawRefreshToken = req.cookies.session;
        const canary_id = req.cookies.canary_id;
        const log = logger.child({service: 'auth', branch: 'access token'})

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
          log.info({token: rawRefreshToken,valid, reason, reqMFA, userId, visitorId},`mfa is triggered`)
        const mfa = await sendTempMfaLink(
          {
          userId: userId!,
          visitor: visitorId!
          }, 
            rawRefreshToken)
            if (!mfa) { 
              log.warn({token: rawRefreshToken,valid, reason, reqMFA, userId, visitorId},`mfa error 500`)
            res.status(500).json({ error: 'Could not send MFA code, try again later' });
            return;
            }
            log.info({token: rawRefreshToken,valid, reason, reqMFA, userId, visitorId},`A login link has been sent to the user`)
            res.status(202).json({ mfa: true, message: 'A login link has been sent to your email.' });
            return;
         }

         if (!valid && !reqMFA) {
          log.info({token: rawRefreshToken,valid, reason, reqMFA, userId, visitorId},`Relogin is required`)
           res.status(401).json({error: 'Relogin is required', reason: reason});
           return;
         }
         
        const hashedToken = createHash('sha256').update(rawRefreshToken).digest('hex');
        if (!(await guard(refreshTokenLimiter, hashedToken, consecutiveForRefreshToken, 1, 'Refresh Token', log, res))) return;

        const compositeKey = `${req.ip}_${hashedToken}`;
        if (!(await guard(refreshAccessTokenLimiter, compositeKey, consecutiveForCompositeKey, 1, 'compositeKey', log, res))) return;

         const result = await verifyRefreshToken(rawRefreshToken);

          if (result.valid && Date.now() - result.sessionTTL!.getTime() >= config.auth.jwt.MAX_SESSION_LIFE) {
           const revoke = await revokeRefreshToken(rawRefreshToken, false);
               if (!revoke.success) {
                   log.error(`DB error revoking token`)
                   res.status(500).json({ error: 'DB error revoking token' });
                   return;
               }
             res.clearCookie('session', {
              httpOnly: true,
              sameSite: "strict", 
              secure: true,
              domain: config.auth.jwt.domain,
              path: '/'
             });
             
             res.clearCookie('iat', {
              httpOnly: true,
              sameSite: "strict", 
              secure: true,
              domain: config.auth.jwt.domain,
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
            jti: crypto.randomUUID()
        });

        resetLimiters(log, hashedToken, [refreshTokenLimiter]);
        consecutiveForRefreshToken.delete(hashedToken);
        log.info({userId: result.userId, visitorId: result.visitor_id},`access token rotated succesfuly`)
        res.status(200).json({ accessToken: accessToken, accessIat: Date.now().toString() });
        return;

      } catch(err) {
        log.error({err},`Error Rotating access token`)
          res.status(500).json({error: `Error Rotating access token: ${err}`})
       }
    };