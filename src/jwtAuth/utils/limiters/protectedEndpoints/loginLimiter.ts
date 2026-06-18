import { RateLimiterMemory, RateLimiterMySQL, RLWrapperBlackAndWhite } from 'rate-limiter-flexible';
import { poolForLibrary } from '../../../config/configuration.js';
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
  const pool = poolForLibrary() as unknown as any;

  const limiterConfig = rate_limiters.loginLimiters;

  const limit = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig.unionLimiter.burstLimiter.inMemoryBlockOnConsumed,
    keyPrefix: 'login',
    points: limiterConfig.unionLimiter.burstLimiter.points,
    tableName: 'login',
    duration: limiterConfig.unionLimiter.burstLimiter.duration, 
    blockDuration: limiterConfig.unionLimiter.burstLimiter.blockDuration,  
    inMemoryBlockDuration: limiterConfig.unionLimiter.burstLimiter.inMemoryBlockDuration 
  });
  
  const slowLimit = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig.unionLimiter.slowLimiter.inMemoryBlockOnConsumed,
    tableName: 'login',
    keyPrefix: 'login_slow_down',
    points: limiterConfig.unionLimiter.slowLimiter.points,
    duration: limiterConfig.unionLimiter.slowLimiter.duration, 
    blockDuration: limiterConfig.unionLimiter.slowLimiter.blockDuration,
    inMemoryBlockDuration: limiterConfig.unionLimiter.slowLimiter.inMemoryBlockDuration 
  });
  
  const ipLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: rate_limiters.loginLimiters.ipLimiter.inMemoryBlockOnConsumed,
    tableName: 'login',
    keyPrefix: 'ip_limiter',
    points: rate_limiters.loginLimiters.ipLimiter.points,
    duration: rate_limiters.loginLimiters.ipLimiter.duration, 
    blockDuration: rate_limiters.loginLimiters.ipLimiter.blockDuration,
    inMemoryBlockDuration: rate_limiters.loginLimiters.ipLimiter.inMemoryBlockDuration 
  }); 
  
  const emailLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: rate_limiters.loginLimiters.emailLimiter.inMemoryBlockOnConsumed,
    tableName: 'login',
    keyPrefix: 'email_limiter',
    points: rate_limiters.loginLimiters.emailLimiter.points,
    duration: rate_limiters.loginLimiters.emailLimiter.duration, 
    blockDuration: rate_limiters.loginLimiters.emailLimiter.blockDuration,
    inMemoryBlockDuration: rate_limiters.loginLimiters.emailLimiter.inMemoryBlockDuration 
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

