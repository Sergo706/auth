import crypto from 'node:crypto'
import type { RequestHandler } from 'express';
import { reject } from './handleRejectedHmac.js';
import { reasons } from '../types/rejects.js';
import { getLogger } from "../utils/logger.js";
import { getConfiguration } from '../config/configuration.js';
import { LRUCache } from "lru-cache";

const nonceCache = new LRUCache<string, boolean>({
    max: 5000,
    ttl: 1000 * 60 * 5 
});
/**
 * Verify inbound requests using HMAC headers and a shared secret.
 *
 * Expected headers:
 * - `X-Client-Id`: client identifier.
 * - `X-Timestamp`: client time in ms.
 * - `X-Signature`: hex HMAC-SHA256 of `id:ts:method:url:reqid`.
 * - `X-Request-ID`: unique request id.
 *
 * Allows unauthenticated local `GET /health`. For other requests, responds 401
 * using `reject()` when validation fails; otherwise calls `next()`.
 */
export const hmacAuth: RequestHandler = (req, res, next) => {
    const {service} = getConfiguration()
    if (!service) return next();
    const SHARED_SECRET = service.Hmac?.sharedSecret
    const EXPECTED_CLIENT_ID = service.Hmac?.clientId;
    const MAX_CLOCK_SKEW_MS = service.Hmac?.maxClockSkew ?? 300000;

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
    reject(reasons.missingHeaders, id, res)
    return;
  }

  if (id !==  EXPECTED_CLIENT_ID) {
    reject(reasons.unknownClient, id, res)
    return;
  }

  if (Math.abs(Date.now() - Number(ts)) > MAX_CLOCK_SKEW_MS!) {
    reject(reasons.timestamp, id, res)
    return;
  }

  if (nonceCache.has(reqid)) {
        reject('Replay detected', id, res);
        return;
  }
  
  const base = `${id}:${ts}:${req.method}:${req.originalUrl}:${reqid}`;
  const expected = crypto.createHmac('sha256', SHARED_SECRET!).update(base).digest('hex');
  const bufExp = Buffer.from(expected, "hex");
  const bufGot = Buffer.from(sig, "hex");


  if (bufExp.length !== bufGot.length || !crypto.timingSafeEqual(bufExp, bufGot)) {
    reject(reasons.buffer, id, res)
    return;
  }

  nonceCache.set(reqid, true, { ttl: MAX_CLOCK_SKEW_MS });
  log.info({Authorized: true, ClientID: id, Reason: 'Match'})

 return next();
}
