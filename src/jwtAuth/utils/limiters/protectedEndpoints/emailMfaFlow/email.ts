import { poolForLibrary } from '../../../../config/dbConnection.js';
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
    const limiterConfig = rate_limiters?.emailMfaLimiters?.unionLimiters;

  const limit = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType: 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig?.limit.inMemoryBlockOnConsumed ?? 1,
    keyPrefix: 'email_mfa',
    points: limiterConfig?.limit.points ?? 1,
    tableName: 'email_mfa',
    duration: limiterConfig?.limit.duration ?? 1, 
    blockDuration: limiterConfig?.limit.blockDuration ?? 1800,  
    inMemoryBlockDuration: limiterConfig?.limit.inMemoryBlockDuration ?? 1800 
  });
  
  const longLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig?.longLimiter.inMemoryBlockOnConsumed ?? 4,
    tableName: 'email_mfa',
    keyPrefix: 'email_mfa_slow_down',
    points: limiterConfig?.longLimiter.points ?? 4,
    duration: limiterConfig?.longLimiter.duration ?? 60 * 30, 
    blockDuration: limiterConfig?.longLimiter.blockDuration ?? 60 * 15,
    inMemoryBlockDuration: limiterConfig?.longLimiter.inMemoryBlockDuration ?? 60 * 15 
  });
  
  const ipLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: rate_limiters?.emailMfaLimiters?.ipLimiter.inMemoryBlockOnConsumed ?? 5,
    tableName: 'email_mfa',
    keyPrefix: 'ip_limiter',
    points: rate_limiters?.emailMfaLimiters?.ipLimiter.points ?? 5,
    duration: rate_limiters?.emailMfaLimiters?.ipLimiter.duration ?? 24 * 60 * 60, 
    blockDuration: rate_limiters?.emailMfaLimiters?.ipLimiter.blockDuration ?? 4 * 60 * 60,
    inMemoryBlockDuration: rate_limiters?.emailMfaLimiters?.ipLimiter.inMemoryBlockDuration ?? 4 * 60 * 60 
  }); 
  
  const userIdLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: rate_limiters?.emailMfaLimiters?.userIdLimiter.inMemoryBlockOnConsumed ?? 5,
    tableName: 'email_mfa',
    keyPrefix: 'userIdLimiter',
    points: rate_limiters?.emailMfaLimiters?.userIdLimiter.points ?? 8,
    duration: rate_limiters?.emailMfaLimiters?.userIdLimiter.duration ?? 24 * 60 * 60, 
    blockDuration: rate_limiters?.emailMfaLimiters?.userIdLimiter.blockDuration ?? 12 * 60 * 60,
    inMemoryBlockDuration: rate_limiters?.emailMfaLimiters?.userIdLimiter.inMemoryBlockDuration ?? 12 * 60 * 60 
  }); 

  const globalEmailLimiter = makeRateLimiter(true, false, {
        dbName: store.rate_limiters_pool.dbName,
        storeClient: pool,
        storeType  : 'mysql2',
        inMemoryBlockOnConsumed: rate_limiters?.emailMfaLimiters?.globalEmailLimiter.inMemoryBlockOnConsumed ?? 5,
        tableName: 'email_mfa',
        keyPrefix: 'globalEmailLimiter',
        points: rate_limiters?.emailMfaLimiters?.globalEmailLimiter.points ?? 800,
        duration: rate_limiters?.emailMfaLimiters?.globalEmailLimiter.duration ?? 24 * 60 * 60, 
        blockDuration: rate_limiters?.emailMfaLimiters?.globalEmailLimiter.blockDuration ?? 24 * 60 * 60,
        inMemoryBlockDuration: rate_limiters?.emailMfaLimiters?.globalEmailLimiter.inMemoryBlockDuration ?? 24 * 60 * 60 
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
