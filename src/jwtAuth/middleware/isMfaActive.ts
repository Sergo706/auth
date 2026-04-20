import { Request, Response, NextFunction } from "express";
import { anomaliesCache } from "~~/utils/anomaliesCache.js";
import { getLogger } from "~~/utils/logger.js";
import crypto from 'node:crypto'

export async function checkForActiveMfa(req: Request, res: Response, next: NextFunction) {
  const rawRefreshToken = req.cookies.session;
  const log = getLogger().child({service: 'auth', branch: 'middleware'})

  if (!rawRefreshToken) {
     next();
    return;
  }

  const hashedToken = crypto.createHash('sha256').update(rawRefreshToken).digest('hex');
  const cached = anomaliesCache()?.get(hashedToken)

  if (cached && !cached.resolved && cached.resolvable) {
    log.info({cached},`This session token has an active MFA`)
    res.status(202).json({ 
        mfa: true, 
        message: 'A login link has been sent to your email.' 
    });
    
    return;
  } else if (cached && !cached.resolved && !cached.resolvable) {
       log.info({cached},`This session is flagged as invalid, and requires a full login`)
       res.status(401).json({error: 'Re-login is required', message: cached.anomalyType});
       return;
  } else {
        next();
        return;
  }
}