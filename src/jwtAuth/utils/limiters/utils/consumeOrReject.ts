import { RateLimiterMemory, RateLimiterMySQL, RateLimiterRes } from "rate-limiter-flexible";
import { Response } from "express";
import { BlockableUnion } from "../rateLimit.js";

type Limiter = RateLimiterMemory | RateLimiterMySQL | BlockableUnion
/**
 * @description
 * Attempts to consume a point for the given rate limiter.  
 * If consumption succeeds, returns the `RateLimiterRes`.  
 * If the limit is reached, sends a 429 response (`Retry-After` header + JSON error) and returns `null`.
 *
 * @param {import('rate-limiter-flexible').RateLimiterAbstract} limiter
 *   The rate limiter instance (e.g., from `rate-limiter-flexible`).
 * @param {string} key
 *   The unique key to consume (e.g., `ip_address_userId`).
 * @param {import('express').Response} res
 *   The Express response object, used to send a 429 when rate limited.
 * @param {import('pino').Logger} log
 *   A Pino logger instance for recording errors or warning events.
 *
 * @returns {Promise<import('rate-limiter-flexible').RateLimiterRes|null>}
 *   Resolves with the `RateLimiterRes` if the point was successfully consumed;
 *   otherwise, `null` after sending a 429 response.
 *
 * @see {@link ./jwtAuth/utils/limiters/utils/consumeOrReject.js}
 *
 * @example
 * const rlRes = await consumeOrReject(limiter, key, res, log);
 * if (rlRes === null) {
 *   // request was rate limited and response was already sent
 * } else {
 *   // continue handling request
 * }
 */
export async function consumeOrReject(
  limiter: Limiter,        
  key: string,
  res: Response,
  log: any
) : Promise<RateLimiterRes | Record<string, RateLimiterRes> | null>{
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

