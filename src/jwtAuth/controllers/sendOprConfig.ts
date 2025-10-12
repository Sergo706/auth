import { Request,Response } from "express";
import { getConfiguration } from "../config/configuration.js";
import { getLogger } from "../utils/logger.js";


export async function sendOperationalConfig (req: Request, res: Response) {

  const log = getLogger().child({    
    ipAddress:  req.ip,
    reqId:      req.id,
    userAgent:  req.get("User-Agent"),
    endpoint:   req.originalUrl,
    service: 'auth',
    branch: 'OprConfig'
});

  const config = getConfiguration();
  const clientIp = config.service?.clientIp ?? config.service?.proxy.ipToTrust;

  if (!clientIp || req.ip !== clientIp) {
    log.warn('Not allowed ip access attempt')
    res.status(403).json({error: 'Forbidden'});
    return;
  }

  const payload = {
    domain: config.jwt.refresh_tokens.domain,
    accessTokenTTL: config.jwt.access_tokens.expiresInMs ?? 1000 * 60 * 15 
  }

  log.info(`Sending OperationalConfig to known client ip`);
  res.status(200).json({...payload})
  return;
}