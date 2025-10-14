import { Request, Response } from "express";
import { revokeRefreshToken, verifyRefreshToken } from "../../refreshTokens.js";
import { getConfiguration } from "../config/configuration.js";
import { getLogger } from "../utils/logger.js";
import { getLimiters } from "../utils/limiters/protectedEndpoints/tokensLimiters.js";
import { makeConsecutiveCache } from "../utils/limiters/utils/consecutiveCache.js";
import { guard } from "../utils/limiters/utils/guard.js";
import { createHash } from "crypto";
import { verifyAccessToken } from "../../accessTokens.js";

const consecutiveForIp = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 10);
const consecutiveForRefreshToken = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 60 * 12);

/**
 * Log out the current session by verifying and revoking the refresh token,
 * blacklisting the access token `jti`, and clearing cookies.
 *
 * Requirements:
 * - `requireRefreshToken` and `requireAccessToken` should run before to populate
 *   `req.cookies.session` and `req.token`.
 * - Applies IP and token-hash rate limits.
 *
 * Responses:
 * - 200: `{ ok: true, message }` after successful revocation and blacklist.
 * - 400: Missing refresh/access token.
 * - 401: Invalid credentials/verification failed.
 * - 500: DB or server error during revocation/blacklist.
 */
export const handleLogout = async (req: Request, res: Response) => {
 const rawRefreshToken = req.cookies.session;
 const accessToken = req.token;
 const log = getLogger().child({service: 'auth', branch: 'logout'});
 const { refreshAccessTokenLimiter, refreshTokenLimiter,blackList } = getLimiters(); 
 const { jwt } = getConfiguration();
 
 
 if (!(await guard(refreshAccessTokenLimiter , req.ip!, consecutiveForIp, 2, 'refreshAccessTokenIpLimiter', log, res))) return;
 
 if (!rawRefreshToken || !accessToken) {
       log.warn(`No refresh or/and access token is provided`);
       res.status(400).json({ok: false, error: 'Invalid Credentials'})
       return;
 }

   const hashedToken = createHash('sha256').update(rawRefreshToken).digest('hex'); 
   if (!(await guard(refreshTokenLimiter, hashedToken, consecutiveForRefreshToken, 1, 'refreshTokenLimiter_logout', log, res))) return;

 try {
  log.info('logging user out...')
  const result = await verifyRefreshToken(rawRefreshToken);

        if (!result.valid) {
          log.warn(`Couldn't revoke a refresh token, because it's not a valid one.`);
          res.status(401).json({ok: false, error: 'Invalid Credentials'})
          return;
        };

        const mark = await revokeRefreshToken(rawRefreshToken);

        if (!mark.success) {
          log.error(`Couldn't revoke a valid refresh token, user can't logged out.`);
          res.status(500).json({ok: false, error: 'Error login user out'})
          return;
        }

        await refreshAccessTokenLimiter.block(hashedToken, Math.floor(jwt.refresh_tokens.refresh_ttl / 1000));
        
        const verified = verifyAccessToken(accessToken);

        if (!verified.valid || !verified.payload) {
          log.warn({errorType: verified.errorType},'Invalid access token');
          res.status(401).json({ok: false, error: 'Invalid Credentials'})
          return;
        }

       const jti = verified.payload.jti;

       if (!jti) {
          log.warn({errorType: verified.errorType, payload: verified.payload},'Invalid access token payload');
          res.status(401).json({ok: false, error: 'Invalid Credentials'})
          return;
       }

          await blackList.block(jti, 60 * 60 * 24);
          log.info({ jti }, 'access token blacklisted for 24h');


       log.info('User logged out successfully');
       res.status(200).json({ok: true, message: 'Logged out successfully'});
       return;

  } catch(err) {
        log.error({err},'Unexpected error type')
        res.status(500).json({ok: false, error: "Server error, can't log user out"})
        return;
  } finally {
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
  } 
}
