import { RateLimiterMemory, RateLimiterMySQL, RLWrapperBlackAndWhite } from 'rate-limiter-flexible';
import { poolForLibary } from '../../../config/dbConnection.js';
import { BlockableUnion, makeRateLimiter, unionLimiter} from '../rateLimit.js'
import { getConfiguration } from '../../../config/configuration.js';

interface LimiterBundle {
  uniLimiter: BlockableUnion | RLWrapperBlackAndWhite;
  ipLimiter: RateLimiterMySQL | RateLimiterMemory;
  emailLimiter: RateLimiterMySQL | RateLimiterMemory;
  resetLimitersUni(key: string): Promise<void>;
}
let limiter: LimiterBundle | null;

function buildLimiter(): LimiterBundle { 
  const { store, rate_limiters } = getConfiguration();
  const pool = poolForLibary() as unknown as any;

  const limiterConfig = rate_limiters?.loginLimiters;

  const limit = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig?.unionLimiter.burstLimiter.inMemoryBlockOnConsumed ?? 1,
    keyPrefix: 'login',
    points: limiterConfig?.unionLimiter.burstLimiter.points ?? 1,
    tableName: 'login',
    duration: limiterConfig?.unionLimiter.burstLimiter.duration ?? 1, 
    blockDuration: limiterConfig?.unionLimiter.burstLimiter.blockDuration ?? 1800,  
    inMemoryBlockDuration: limiterConfig?.unionLimiter.burstLimiter.inMemoryBlockDuration ?? 1800 
  });
  
  const slowLimit = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig?.unionLimiter.slowLimiter.inMemoryBlockOnConsumed ?? 5,
    tableName: 'login',
    keyPrefix: 'login_slow_down',
    points: limiterConfig?.unionLimiter.slowLimiter.points ?? 5,
    duration: limiterConfig?.unionLimiter.slowLimiter.duration ?? 60 * 60, 
    blockDuration: limiterConfig?.unionLimiter.slowLimiter.blockDuration ?? 60 * 30,
    inMemoryBlockDuration: limiterConfig?.unionLimiter.slowLimiter.inMemoryBlockDuration ?? 60 * 30 
  });
  
  const ipLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: rate_limiters?.loginLimiters?.ipLimiter.inMemoryBlockOnConsumed ?? 15,
    tableName: 'login',
    keyPrefix: 'ip_limiter',
    points: rate_limiters?.loginLimiters?.ipLimiter.points ?? 15,
    duration: rate_limiters?.loginLimiters?.ipLimiter.duration ?? 24 * 60 * 60, 
    blockDuration: rate_limiters?.loginLimiters?.ipLimiter.blockDuration ?? 3 * 60 * 60,
    inMemoryBlockDuration: rate_limiters?.loginLimiters?.ipLimiter.inMemoryBlockDuration ?? 3 * 60 * 60 
  }); 
  
  const emailLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: rate_limiters?.loginLimiters?.emailLimiter.inMemoryBlockOnConsumed ?? 5,
    tableName: 'login',
    keyPrefix: 'email_limiter',
    points: rate_limiters?.loginLimiters?.emailLimiter.points ?? 5,
    duration: rate_limiters?.loginLimiters?.emailLimiter.duration ?? 24 * 60 * 60, 
    blockDuration: rate_limiters?.loginLimiters?.emailLimiter.blockDuration ?? 5 * 60 * 60,
    inMemoryBlockDuration: rate_limiters?.loginLimiters?.emailLimiter.inMemoryBlockDuration ?? 5 * 60 * 60 
  }); 

 return {
  uniLimiter: unionLimiter([limit, slowLimit ], false),
  ipLimiter,
  emailLimiter,
  resetLimitersUni: async (key: string) => {
   await Promise.all([
    limit.delete(key),        
    slowLimit.delete(key), 
    ipLimiter.delete(key),
    emailLimiter.delete(key),
  ])
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
  const { uniLimiter, ipLimiter, emailLimiter } = ensureLimiter();
  return { uniLimiter, ipLimiter, emailLimiter };
}

export function resetLimitersUni(key: string) {
  return ensureLimiter().resetLimitersUni(key);
}

