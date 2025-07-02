import { RateLimiterRes } from "rate-limiter-flexible";
import { Response } from "express";

export async function consumeOrReject(
  limiter: any,        
  key: string,
  res: Response,
  log: any
) : Promise<RateLimiterRes | null>{
  try {
    return await limiter.consume(key);
  } catch (err: any) {
    if (err instanceof Error) {
       log.error({error: err, limiter: limiter, key: key},`error rate limiting in uniLimiter`);
       throw err;
    } else {
      const retrySec = Math.ceil(err.msBeforeNext / 1000) || 1;
     log.warn({ error: err, ip: key.split('_')[0], limiter: limiter.keyPrefix , rawKey: key}, 'A visitor has been rate limited');
      res.set('Retry-After', String(retrySec)).status(429).json({
        error: 'Too many requests',
        retry: retrySec,
      });
      return null;
    }
  }
}

