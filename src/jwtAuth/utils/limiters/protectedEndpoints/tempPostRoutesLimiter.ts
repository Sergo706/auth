import { poolForLibary } from '../../../config/dbConnection.js';
import { BlockableUnion, makeRateLimiter, unionLimiter} from '../rateLimit.js'
import { getConfiguration } from '../../../config/configuration.js';
import { RateLimiterMemory, RateLimiterMySQL, RLWrapperBlackAndWhite } from 'rate-limiter-flexible';




interface LimiterBundle {
  uniLimiter: BlockableUnion | RLWrapperBlackAndWhite;
  ipLimit: RateLimiterMySQL | RateLimiterMemory;
  resetCompositeKey(key: string): Promise<void>;
}

let limiter: LimiterBundle | null;

function buildLimiter(): LimiterBundle { 
  const { store, rate_limiters } = getConfiguration();
  const pool = poolForLibary() as unknown as any;
  const limiterConfig = rate_limiters?.tempPostRoutesLimiters?.unionLimiters;

  const limit = makeRateLimiter(true, false, {
    dbName: store.databaseName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig?.limit.inMemoryBlockOnConsumed ?? 1,
    keyPrefix: 'tempPostRoutes_brute',
    points: limiterConfig?.limit.points ?? 1,
    tableName: 'tempPostRoutes',
    duration: limiterConfig?.limit.duration ?? 1, 
    blockDuration: limiterConfig?.limit.blockDuration ?? 1800,  
    inMemoryBlockDuration: limiterConfig?.limit.inMemoryBlockDuration ?? 1800 
  });
  
  const slowLimit = makeRateLimiter(true, false, {
    dbName: store.databaseName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig?.slowLimit.inMemoryBlockOnConsumed ?? 5,
    keyPrefix: 'tempPostRoutes_slow',
    points: limiterConfig?.slowLimit.points ?? 5,
    tableName: 'tempPostRoutes',
    duration: limiterConfig?.slowLimit.duration ?? 60 * 10, 
    blockDuration: limiterConfig?.slowLimit.blockDuration ?? 60 * 10,  
    inMemoryBlockDuration: limiterConfig?.slowLimit.inMemoryBlockDuration ?? 60 * 10 
  });
  
  const ipLimit = makeRateLimiter(true, false, {
    dbName: store.databaseName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: rate_limiters?.tempPostRoutesLimiters?.ipLimit.inMemoryBlockOnConsumed ?? 6,
    keyPrefix: 'tempPostRoutes_ip',
    points: rate_limiters?.tempPostRoutesLimiters?.ipLimit.points ?? 6,
    tableName: 'tempPostRoutes',
    duration: rate_limiters?.tempPostRoutesLimiters?.ipLimit.duration ?? 60 * 10, 
    blockDuration: rate_limiters?.tempPostRoutesLimiters?.ipLimit.blockDuration ?? 60 * 10,  
    inMemoryBlockDuration: rate_limiters?.tempPostRoutesLimiters?.ipLimit.inMemoryBlockDuration ?? 60 * 10 
  });

  return {
    uniLimiter: unionLimiter([limit, slowLimit ], false),
    ipLimit,
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
  const { uniLimiter, ipLimit } = ensureLimiter();
  return {uniLimiter, ipLimit};
}

export function resetLimitersUni(key: string) {
  return ensureLimiter().resetCompositeKey(key)
}
