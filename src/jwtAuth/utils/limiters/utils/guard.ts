import { LRUCache } from "lru-cache";
import { consumeOrReject } from "./consumeOrReject.js";
import { Response } from "express";
import { RateLimiterMemory, RateLimiterMySQL, RateLimiterRes, RLWrapperBlackAndWhite, RateLimiterUnion } from 'rate-limiter-flexible';
import pino from "pino";
import { BlockableUnion } from "../rateLimit.js";
import { makeConsecutiveCache } from "./consecutiveCache.js";

type Limiter = RateLimiterMemory | RateLimiterMySQL | BlockableUnion

interface CacheEntry {
  countData: number;
}

const isBlockedCache =  makeConsecutiveCache<{Blocked: boolean, expire: Date | string}>(1000, 1000 * 60 * 60 * 24 * 7);
/**
 * @description
 * Guard an endpoint using the provided rate limiter and an LRU cache to track ban strikes.
 * If a key exceeds the allowed strikes (maxBans), it is blacklisted. Otherwise, each rate-limit
 * event increments the strike counter in the cache. On ban or rate-limit, a response is sent.
 *
 * @param {import('rate-limiter-flexible').RateLimiterAbstract} limiter
 *   The rate limiter instance to consume points from.
 * @param {string} key
 *   The unique key for rate-limiting (e.g., IP address or user ID).
 * @param {import('lru-cache').LRUCache<string, { Blocked: boolean; expire: Date | string }>} cache
 *   An LRU cache tracking how many times a key has been rate-limited and ban state.
 * @param {number} maxBans
 *   Maximum number of strikes before blacklisting the key.
 * @param {string} label
 *   A label describing the limiter’s purpose (e.g., 'login', 'password-reset').
 * @param {import('pino').Logger} log
 *   A Pino logger instance for recording events and errors.
 * @param {import('express').Response} res
 *   The Express response object used to send 429 or ban responses.
 * @param {number} [seconds]
 *   Optional custom ban duration in seconds (overrides cache entry’s TTL).
 *
 * @returns {Promise<boolean>}
 *   Resolves to:
 *   - `true` if the request may proceed,
 *   - `false` if the limiter blocked or banned the key (response has already been sent).
 *
 * @see {@link ./jwtAuth/utils/limiters/utils/guard.js}
 *
 * @example
 * import pino from 'pino';
 * const log = pino();
 * const cache = makeConsecutiveCache<{ Blocked: boolean; expire: Date | string }>(1000, 7 * 24 * 60 * 60 * 1000);
 *
 * app.post('/login', async (req, res) => {
 *   const key = req.ip;
 *   if (!(await guard(loginLimiter, key, cache, 3, 'login', log, res, 3600))) {
 *     return; // guard already sent 429 or ban response
 *   }
 *   // proceed with login logic
 * });
 */
export async function guard(
  limiter: Limiter,
  key: string,
  cache: LRUCache<string, CacheEntry>,
  maxBans: number,
  label: string,
  log: pino.Logger,
  res: Response,
  seconds?: number
): Promise<boolean> {
  
    if (isBlockedCache.get(key)?.Blocked) {
    log.warn({ key, label, limiters: limiter.keyPrefix, expires: isBlockedCache.get(key)?.expire}, 'Request blocked by cache');
    res.set('Retry-After', String(isBlockedCache.get(key)?.expire)).status(429).json(
      { error: 'Too many requests',
        retry: isBlockedCache.get(key)?.expire
      });
    return false;
  }

  const rlRes: RateLimiterRes | null = await consumeOrReject(limiter, key, res, log);
  
  if (rlRes === null) {
    const entry = (cache.get(key)?.countData ?? 0) + 1;
    cache.set(key, { countData: entry });

    log.warn({ key, label, entry }, 'Strike recorded');

    if (entry >= maxBans) { 
        await limiter.block(key, seconds ?? 0);
        isBlockedCache.set(key, {Blocked: true, expire: `${seconds ?? 'permanent'}` })
        log.warn({ key, label, limiters: limiter.keyPrefix}, `Key added to ${seconds ?? 'permanent'} duration blacklist`);
    }
    return false; 
  }

  isBlockedCache.delete(key);
  log.info({ key, label, remaining: rlRes.remainingPoints, consumed: rlRes.consumedPoints, nextActionAllowedIn: rlRes.msBeforeNext }, 'Limiter passed');
  return true;  
}

