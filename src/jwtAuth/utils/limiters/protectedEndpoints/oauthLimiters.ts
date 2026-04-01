import { poolForLibrary } from '../../../config/configuration.js';
import { BlockableUnion, makeRateLimiter, unionLimiter} from '../rateLimit.js'
import { getConfiguration } from '../../../config/configuration.js';
import { RateLimiterMemory, RateLimiterMySQL, RLWrapperBlackAndWhite } from 'rate-limiter-flexible';


interface LimiterBundle {
  uniLimiter: BlockableUnion | RLWrapperBlackAndWhite;
  subLimiter: RateLimiterMySQL | RateLimiterMemory;
  compositeKeyLimiter: RateLimiterMySQL | RateLimiterMemory;
}
let limiter: LimiterBundle | null;


function buildLimiter(): LimiterBundle { 

  const { store, rate_limiters } = getConfiguration();
  const pool = poolForLibrary() as unknown as any;
  const limiterConfig = rate_limiters?.oauthLimiters?.unionLimiter;
  
  const ipLimiterBrute = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig?.ipLimiterBrute.inMemoryBlockOnConsumed ?? 1,
    keyPrefix: 'oauth_ip_brute',
    points: limiterConfig?.ipLimiterBrute.points ?? 1,
    tableName: 'oauth',
    duration: limiterConfig?.ipLimiterBrute.duration ?? 1, 
    blockDuration: limiterConfig?.ipLimiterBrute.blockDuration ?? 60 * 5,  
    inMemoryBlockDuration: limiterConfig?.ipLimiterBrute.inMemoryBlockDuration ?? 60 * 5 
  });
  
  const ipLimiterSlow = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig?.ipLimiterSlow.inMemoryBlockOnConsumed ?? 25,
    keyPrefix: 'oauth_ip_slow',
    points: limiterConfig?.ipLimiterSlow.points ?? 25,
    tableName: 'oauth',
    duration: limiterConfig?.ipLimiterSlow.duration ?? 60 * 60, 
    blockDuration: limiterConfig?.ipLimiterSlow.blockDuration ?? 60 * 30,  
    inMemoryBlockDuration: limiterConfig?.ipLimiterSlow.inMemoryBlockDuration ?? 60 * 30 
  });
  
   const subLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: rate_limiters?.oauthLimiters?.subLimiter.inMemoryBlockOnConsumed ?? 5,
    keyPrefix: 'oauth_sub',
    points: rate_limiters?.oauthLimiters?.subLimiter.points ?? 5,
    tableName: 'oauth',
    duration: rate_limiters?.oauthLimiters?.subLimiter.duration ?? 60 * 5, 
    blockDuration: rate_limiters?.oauthLimiters?.subLimiter.blockDuration ?? 60 * 15,  
    inMemoryBlockDuration: rate_limiters?.oauthLimiters?.subLimiter.inMemoryBlockDuration ?? 60 * 15 
  });
  
   const compositeKeyLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: rate_limiters?.oauthLimiters?.compositeKeyLimiter.inMemoryBlockOnConsumed ?? 3,
    keyPrefix: 'oauth_compositeKey',
    points: rate_limiters?.oauthLimiters?.compositeKeyLimiter.points ?? 3,
    tableName: 'oauth',
    duration: rate_limiters?.oauthLimiters?.compositeKeyLimiter.duration ?? 60 * 10, 
    blockDuration: rate_limiters?.oauthLimiters?.compositeKeyLimiter.blockDuration ?? 60 * 15,  
    inMemoryBlockDuration: rate_limiters?.oauthLimiters?.compositeKeyLimiter.inMemoryBlockDuration ?? 60 * 15 
  });
 return {
  uniLimiter: unionLimiter([ipLimiterBrute, ipLimiterSlow ], false),
  subLimiter,
  compositeKeyLimiter
 }
}


function ensureLimiter(): LimiterBundle {
  if (!limiter) {
    limiter = buildLimiter();
  }
  return limiter;
}

export function getLimiters() {
  const { uniLimiter, subLimiter, compositeKeyLimiter } = ensureLimiter();
  return { uniLimiter, subLimiter, compositeKeyLimiter };
}

