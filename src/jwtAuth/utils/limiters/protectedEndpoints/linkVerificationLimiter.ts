import { poolForLibrary } from '../../../config/configuration.js';
import { getConfiguration } from '../../../config/configuration.js';
import {BlockableUnion, makeRateLimiter, unionLimiter} from '../rateLimit.js'
import { RLWrapperBlackAndWhite } from 'rate-limiter-flexible';


interface LimiterBundle {
  uniLimiter: BlockableUnion | RLWrapperBlackAndWhite;
  resetLimitersUni(key: string): Promise<void>;
}
let limiter: LimiterBundle | null;

function buildLimiter(): LimiterBundle { 
  const { store, rate_limiters } = getConfiguration();
  const pool = poolForLibrary() as unknown as any;
  const limiterConfig = rate_limiters?.linkVerificationLimiter?.unionLimiter;

const limit = makeRateLimiter(true, false, {
  dbName: store.rate_limiters_pool.dbName,
  storeClient: pool,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: limiterConfig?.burstLimiter.inMemoryBlockOnConsumed ?? 2,
  keyPrefix: 'link_verification_brute',
  points: limiterConfig?.burstLimiter.points ?? 2,
  tableName: 'link_verification',
  duration: limiterConfig?.burstLimiter.duration ?? 1, 
  blockDuration: limiterConfig?.burstLimiter.blockDuration ?? 60 * 15,  
  inMemoryBlockDuration: limiterConfig?.burstLimiter.inMemoryBlockDuration ?? 60 * 15 
});

const slowLimit = makeRateLimiter(true, false, {
  dbName: store.rate_limiters_pool.dbName,
  storeClient: pool,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: limiterConfig?.slowLimiter.inMemoryBlockOnConsumed ?? 30,
  keyPrefix: 'link_verification_slow',
  points: limiterConfig?.slowLimiter.points ?? 30,
  tableName: 'link_verification',
  duration: limiterConfig?.slowLimiter.duration ?? 60 * 30, 
  blockDuration: limiterConfig?.slowLimiter.blockDuration ?? 1800,  
  inMemoryBlockDuration: limiterConfig?.slowLimiter.inMemoryBlockDuration ?? 1800 
});
 return {
  uniLimiter: unionLimiter([limit, slowLimit ], false),
  resetLimitersUni: async (key: string) => {
   await Promise.all([limit.delete(key), slowLimit.delete(key)])
  }
 }
}

function ensureLimiter(): LimiterBundle {
  if (!limiter) {
    limiter = buildLimiter();
  }
  return limiter;
}

export function getUniLimiter() {
  return ensureLimiter().uniLimiter;
}

export function resetLimitersUni(key: string) {
  return ensureLimiter().resetLimitersUni(key);
}