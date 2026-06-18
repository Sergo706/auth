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
  const limiterConfig = rate_limiters.oauthLimiters.unionLimiter;
  
  const ipLimiterBrute = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig.ipLimiterBrute.inMemoryBlockOnConsumed,
    keyPrefix: 'oauth_ip_brute',
    points: limiterConfig.ipLimiterBrute.points,
    tableName: 'oauth',
    duration: limiterConfig.ipLimiterBrute.duration, 
    blockDuration: limiterConfig.ipLimiterBrute.blockDuration,  
    inMemoryBlockDuration: limiterConfig.ipLimiterBrute.inMemoryBlockDuration 
  });
  
  const ipLimiterSlow = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig.ipLimiterSlow.inMemoryBlockOnConsumed,
    keyPrefix: 'oauth_ip_slow',
    points: limiterConfig.ipLimiterSlow.points,
    tableName: 'oauth',
    duration: limiterConfig.ipLimiterSlow.duration, 
    blockDuration: limiterConfig.ipLimiterSlow.blockDuration,  
    inMemoryBlockDuration: limiterConfig.ipLimiterSlow.inMemoryBlockDuration 
  });
  
   const subLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: rate_limiters.oauthLimiters.subLimiter.inMemoryBlockOnConsumed,
    keyPrefix: 'oauth_sub',
    points: rate_limiters.oauthLimiters.subLimiter.points,
    tableName: 'oauth',
    duration: rate_limiters.oauthLimiters.subLimiter.duration, 
    blockDuration: rate_limiters.oauthLimiters.subLimiter.blockDuration,  
    inMemoryBlockDuration: rate_limiters.oauthLimiters.subLimiter.inMemoryBlockDuration 
  });
  
   const compositeKeyLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: rate_limiters.oauthLimiters.compositeKeyLimiter.inMemoryBlockOnConsumed,
    keyPrefix: 'oauth_compositeKey',
    points: rate_limiters.oauthLimiters.compositeKeyLimiter.points,
    tableName: 'oauth',
    duration: rate_limiters.oauthLimiters.compositeKeyLimiter.duration, 
    blockDuration: rate_limiters.oauthLimiters.compositeKeyLimiter.blockDuration,  
    inMemoryBlockDuration: rate_limiters.oauthLimiters.compositeKeyLimiter.inMemoryBlockDuration 
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

