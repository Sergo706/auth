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
  const limiterConfig = rate_limiters.linkVerificationLimiter.unionLimiter;

const limit = makeRateLimiter(true, false, {
  dbName: store.rate_limiters_pool.dbName,
  storeClient: pool,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: limiterConfig.burstLimiter.inMemoryBlockOnConsumed,
  keyPrefix: 'link_verification_brute',
  points: limiterConfig.burstLimiter.points,
  tableName: 'link_verification',
  duration: limiterConfig.burstLimiter.duration, 
  blockDuration: limiterConfig.burstLimiter.blockDuration,  
  inMemoryBlockDuration: limiterConfig.burstLimiter.inMemoryBlockDuration 
});

const slowLimit = makeRateLimiter(true, false, {
  dbName: store.rate_limiters_pool.dbName,
  storeClient: pool,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: limiterConfig.slowLimiter.inMemoryBlockOnConsumed,
  keyPrefix: 'link_verification_slow',
  points: limiterConfig.slowLimiter.points,
  tableName: 'link_verification',
  duration: limiterConfig.slowLimiter.duration, 
  blockDuration: limiterConfig.slowLimiter.blockDuration,  
  inMemoryBlockDuration: limiterConfig.slowLimiter.inMemoryBlockDuration 
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