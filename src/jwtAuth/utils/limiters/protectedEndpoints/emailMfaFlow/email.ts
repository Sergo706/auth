import { poolForLibrary } from '../../../../config/configuration.js';
import { BlockableUnion, makeRateLimiter, unionLimiter} from '../../rateLimit.js'
import { getConfiguration } from '../../../../config/configuration.js';
import { RateLimiterMemory, RateLimiterMySQL, RLWrapperBlackAndWhite } from 'rate-limiter-flexible';



interface LimiterBundle {
  uniLimiter: BlockableUnion | RLWrapperBlackAndWhite;
  ipLimiter: RateLimiterMemory | RateLimiterMySQL;
  userIdLimiter: RateLimiterMemory | RateLimiterMySQL;
  globalEmailLimiter: RateLimiterMemory | RateLimiterMySQL;
  resetUnionLimiter(key: string): Promise<void>;
}

let limiter: LimiterBundle | null;

function buildLimiter(): LimiterBundle {
    const { store, rate_limiters } = getConfiguration();
    const pool = poolForLibrary();
    const limiterConfig = rate_limiters.emailMfaLimiters.unionLimiters;

  const limit = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType: 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig.limit.inMemoryBlockOnConsumed,
    keyPrefix: 'email_mfa',
    points: limiterConfig.limit.points,
    tableName: 'email_mfa',
    duration: limiterConfig.limit.duration, 
    blockDuration: limiterConfig.limit.blockDuration,  
    inMemoryBlockDuration: limiterConfig.limit.inMemoryBlockDuration 
  });
  
  const longLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig.longLimiter.inMemoryBlockOnConsumed,
    tableName: 'email_mfa',
    keyPrefix: 'email_mfa_slow_down',
    points: limiterConfig.longLimiter.points,
    duration: limiterConfig.longLimiter.duration, 
    blockDuration: limiterConfig.longLimiter.blockDuration,
    inMemoryBlockDuration: limiterConfig.longLimiter.inMemoryBlockDuration 
  });
  
  const ipLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: rate_limiters.emailMfaLimiters.ipLimiter.inMemoryBlockOnConsumed,
    tableName: 'email_mfa',
    keyPrefix: 'ip_limiter',
    points: rate_limiters.emailMfaLimiters.ipLimiter.points,
    duration: rate_limiters.emailMfaLimiters.ipLimiter.duration, 
    blockDuration: rate_limiters.emailMfaLimiters.ipLimiter.blockDuration,
    inMemoryBlockDuration: rate_limiters.emailMfaLimiters.ipLimiter.inMemoryBlockDuration 
  }); 
  
  const userIdLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: rate_limiters.emailMfaLimiters.userIdLimiter.inMemoryBlockOnConsumed,
    tableName: 'email_mfa',
    keyPrefix: 'userIdLimiter',
    points: rate_limiters.emailMfaLimiters.userIdLimiter.points,
    duration: rate_limiters.emailMfaLimiters.userIdLimiter.duration, 
    blockDuration: rate_limiters.emailMfaLimiters.userIdLimiter.blockDuration,
    inMemoryBlockDuration: rate_limiters.emailMfaLimiters.userIdLimiter.inMemoryBlockDuration 
  }); 

  const globalEmailLimiter = makeRateLimiter(true, false, {
        dbName: store.rate_limiters_pool.dbName,
        storeClient: pool,
        storeType  : 'mysql2',
        inMemoryBlockOnConsumed: rate_limiters.emailMfaLimiters.globalEmailLimiter.inMemoryBlockOnConsumed,
        tableName: 'email_mfa',
        keyPrefix: 'globalEmailLimiter',
        points: rate_limiters.emailMfaLimiters.globalEmailLimiter.points,
        duration: rate_limiters.emailMfaLimiters.globalEmailLimiter.duration, 
        blockDuration: rate_limiters.emailMfaLimiters.globalEmailLimiter.blockDuration,
        inMemoryBlockDuration: rate_limiters.emailMfaLimiters.globalEmailLimiter.inMemoryBlockDuration 
  }); 

  return {
    uniLimiter: unionLimiter([limit, longLimiter ], false),
    ipLimiter,
    userIdLimiter,
    globalEmailLimiter,
    resetUnionLimiter: async (key: string) => {
    await Promise.all([
    limit.delete(key),        
    longLimiter.delete(key)
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
  const { uniLimiter, ipLimiter, userIdLimiter, globalEmailLimiter } = ensureLimiter();
  return {uniLimiter, ipLimiter, userIdLimiter, globalEmailLimiter };
}

export function resetLimitersUni(key: string) {
  return ensureLimiter().resetUnionLimiter(key)
}
