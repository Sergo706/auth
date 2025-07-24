import { Request, Response } from "express";
import { revokeRefreshToken, verifyRefreshToken } from "../../refreshTokens.js";
import { getConfiguration } from "../config/configuration.js";
import { getLogger } from "../utils/logger.js";
import { getLimiters } from "../utils/limiters/protectedEndpoints/tokensLimiters.js";
import { makeConsecutiveCache } from "../utils/limiters/utils/consecutiveCache.js";
import { guard } from "../utils/limiters/utils/guard.js";
import { createHash } from "crypto";

const consecutiveForIp = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 10);
const consecutiveForRefreshToken = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 60 * 12);

export const handleLogout = async (req: Request, res: Response) => {
 const rawRefreshToken = req.cookies.session;
 const log = getLogger().child({service: 'auth', branch: 'logout'});
 const { refreshAccessTokenLimiter, refreshTokenLimiter } = getLimiters(); 
 const { jwt } = getConfiguration();
 
   if (!(await guard(refreshAccessTokenLimiter , req.ip!, consecutiveForIp, 2, 'refreshAccessTokenIpLimiter', log, res))) return;
   
   const hashedToken = createHash('sha256').update(rawRefreshToken).digest('hex'); 
   if (!(await guard(refreshTokenLimiter, hashedToken, consecutiveForRefreshToken, 1, 'refreshTokenLimiter_logout', log, res))) return;

 try {
  log.info('loggin user out...')
  const result = await verifyRefreshToken(rawRefreshToken);
    
        if (result.valid) {
          const markToken = await revokeRefreshToken(rawRefreshToken);
            if (markToken.success) {
                res.clearCookie('session', {
                    httpOnly: true,
                    sameSite: "strict", 
                    secure: true,
                    domain: jwt.refresh_tokens.domain,
                    path: '/'
                });
                await refreshAccessTokenLimiter.block(hashedToken, 60 * 60 * 24 * 3);
                log.info('Session deleted successfully, and user is logged out')
                res.status(200).json({session: 'Session deleted successfully!', userID: result.userId})
                return;
            }
        };

        if (!result.valid) {
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
            await refreshAccessTokenLimiter.block(hashedToken, 60 * 60 * 24 * 3);
            log.warn('No refresh record are found, but cookie was deleted')
            res.status(200).json({session: 'No refresh record are found, but cookie was deleted'})
            return;
        };
  } catch(err) {
        log.error({err},'Error login user out')
        res.status(500).json({session: 'Error login out'})
  }  
}
