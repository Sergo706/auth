import { poolForLibrary } from '../../../config/configuration.js';
import { BlockableUnion, makeRateLimiter, unionLimiter} from '../rateLimit.js'
import { getConfiguration } from '../../../config/configuration.js';
import { RateLimiterMemory, RateLimiterMySQL, RLWrapperBlackAndWhite } from 'rate-limiter-flexible';




interface LimiterBundle {
  uniLimiter: BlockableUnion | RLWrapperBlackAndWhite;
  ipLimit: RateLimiterMySQL | RateLimiterMemory;
  usedJtiLimiter: RateLimiterMySQL | RateLimiterMemory;
  resetCompositeKey(key: string): Promise<void>;
}

let limiter: LimiterBundle | null;

function buildLimiter(): LimiterBundle { 
  const { store, rate_limiters } = getConfiguration();
  const pool = poolForLibrary() as unknown as any;
  const limiterConfig = rate_limiters.tempPostRoutesLimiters.unionLimiters;

  const limit = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig.limit.inMemoryBlockOnConsumed,
    keyPrefix: 'tempPostRoutes_brute',
    points: limiterConfig.limit.points,
    tableName: 'tempPostRoutes',
    duration: limiterConfig.limit.duration, 
    blockDuration: limiterConfig.limit.blockDuration,  
    inMemoryBlockDuration: limiterConfig.limit.inMemoryBlockDuration 
  });
  
  const slowLimit = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig.slowLimit.inMemoryBlockOnConsumed,
    keyPrefix: 'tempPostRoutes_slow',
    points: limiterConfig.slowLimit.points,
    tableName: 'tempPostRoutes',
    duration: limiterConfig.slowLimit.duration, 
    blockDuration: limiterConfig.slowLimit.blockDuration,  
    inMemoryBlockDuration: limiterConfig.slowLimit.inMemoryBlockDuration 
  });
  
  const ipLimit = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: rate_limiters.tempPostRoutesLimiters.ipLimit.inMemoryBlockOnConsumed,
    keyPrefix: 'tempPostRoutes_ip',
    points: rate_limiters.tempPostRoutesLimiters.ipLimit.points,
    tableName: 'tempPostRoutes',
    duration: rate_limiters.tempPostRoutesLimiters.ipLimit.duration, 
    blockDuration: rate_limiters.tempPostRoutesLimiters.ipLimit.blockDuration,  
    inMemoryBlockDuration: rate_limiters.tempPostRoutesLimiters.ipLimit.inMemoryBlockDuration 
  });

  const usedJtiLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    points: 0,
    duration: 0,       
    blockDuration: 20 * 60,  
    keyPrefix: 'used_jti',
    tableName: 'tempPostRoutes',
  });

  return {
    uniLimiter: unionLimiter([limit, slowLimit ], false),
    ipLimit,
    usedJtiLimiter,
    resetCompositeKey: async (key: string) => {
     await Promise.all([
      limit.delete(key),        
      slowLimit.delete(key), 
  ]);
}
  }

}



function ensureLimiter(): LimiterBundle {
  if (!limiter) {
    limiter = buildLimiter();
  }
  return limiter;
}

export function getLimiters() {
  const { uniLimiter, ipLimit, usedJtiLimiter } = ensureLimiter();
  return {uniLimiter, ipLimit, usedJtiLimiter};
}

export function resetLimitersUni(key: string) {
  return ensureLimiter().resetCompositeKey(key)
}
