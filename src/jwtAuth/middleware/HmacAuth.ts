import crypto from 'node:crypto'
import type { RequestHandler } from 'express';
import { reject } from './handleRejectedHmac.js';
import { reasons } from '../types/rejects.js';
import { getLogger } from "../utils/logger.js";
import { getConfiguration } from '../config/configuration.js';


export const hmacAuth: RequestHandler = (req, res, next) => {
    const {service} = getConfiguration()
    if (!service) return next();
    const SHARED_SECRET = service.Hmac?.sharedSecret
    const EXPECTED_CLIENT_ID = service.Hmac?.clientId;
    const MAX_CLOCK_SKEW_MS = service.Hmac?.maxClockSkew;

    const id = req.get('X-Client-Id');
    const ts = req.get('X-Timestamp');
    const sig = req.get('X-Signature');
    const reqid = req.get('X-Request-ID')
    const log = getLogger().child({service: 'HMAC', clientId: id});

    const remote = req.ip || req.socket.remoteAddress || '';
    const isLocal = remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1';
    const isHealth = req.method === 'GET' && (req.path === '/health' || req.originalUrl === '/health');

    if (isHealth && isLocal) return next();
    

  if (!id || !ts || !sig || !reqid) {
    reject(reasons.missingHeaders, parseInt(id!), res)
    return;
  }

  if (id !==  EXPECTED_CLIENT_ID) {
    reject(reasons.unknownClient, parseInt(id!), res)
    return;
  }

  if (Math.abs(Date.now() - Number(ts)) > MAX_CLOCK_SKEW_MS!) {
    reject(reasons.timestamp, parseInt(id!), res)
    return;
  }

  const base = `${id}:${ts}:${req.method}:${req.originalUrl}:${reqid}`;
  const expected = crypto.createHmac('sha256', SHARED_SECRET!).update(base).digest('hex');
  const bufExp = Buffer.from(expected, "hex");
  const bufGot = Buffer.from(sig, "hex");


  if (bufExp.length !== bufGot.length || !crypto.timingSafeEqual(bufExp, bufGot)) {
    reject(reasons.buffer, parseInt(id!), res)
    return;
  }
  log.info({Authorized: true, ClientID: id, Reason: 'Match'})

 return next();
}