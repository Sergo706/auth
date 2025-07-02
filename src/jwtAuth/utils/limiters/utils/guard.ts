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
/**
 * Run a limiter and keep a strike‐counter in an LRU cache.
 * @returns true  – request may proceed
 *          false – limiter blocked and the helper already answered the client
*/
const isBlockedCache =  makeConsecutiveCache<{Blocked: boolean, expire: Date | string}>(1000, 1000 * 60 * 60 * 24 * 7);
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

