import { poolForLibrary } from '../../../../config/configuration.js';
import { BlockableUnion, makeRateLimiter, unionLimiter} from '../../rateLimit.js'
import { getConfiguration } from '../../../../config/configuration.js';
import { RateLimiterMemory, RateLimiterMySQL, RLWrapperBlackAndWhite } from 'rate-limiter-flexible';



interface LimiterBundle {
  uniLimiter: BlockableUnion | RLWrapperBlackAndWhite;
  ipLimiter: RateLimiterMemory | RateLimiterMySQL;
  emailLimiter: RateLimiterMemory | RateLimiterMySQL;
  resetUnionLimiter(key: string): Promise<void>;
}

let limiter: LimiterBundle | null;

function buildLimiter(): LimiterBundle { 
  const { store, rate_limiters } = getConfiguration();
  const pool = poolForLibrary() as unknown as any;
  const limiterConfig = rate_limiters?.initPasswordResetLimiters?.unionLimiters;

  const limit = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig?.limit.inMemoryBlockOnConsumed ?? 1,
    keyPrefix: 'password_reset',
    points: limiterConfig?.limit.points ?? 1,
    tableName: 'password_reset',
    duration: limiterConfig?.limit.duration ?? 1, 
    blockDuration: limiterConfig?.limit.blockDuration ?? 1800,  
    inMemoryBlockDuration: limiterConfig?.limit.inMemoryBlockDuration ?? 1800 
  });
  
  const longLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig?.longLimiter.inMemoryBlockOnConsumed ?? 4,
    tableName: 'password_reset',
    keyPrefix: 'password_reset_slow_down',
    points: limiterConfig?.longLimiter.points ?? 4,
    duration: limiterConfig?.longLimiter.duration ?? 60 * 30, 
    blockDuration: limiterConfig?.longLimiter.blockDuration ?? 60 * 15,
    inMemoryBlockDuration: limiterConfig?.longLimiter.inMemoryBlockDuration ?? 60 * 15 
  });
  
  const ipLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: rate_limiters?.initPasswordResetLimiters?.ipLimiter.inMemoryBlockOnConsumed ?? 5,
    tableName: 'password_reset',
    keyPrefix: 'ip_limiter',
    points: rate_limiters?.initPasswordResetLimiters?.ipLimiter.points ?? 5,
    duration: rate_limiters?.initPasswordResetLimiters?.ipLimiter.duration ?? 24 * 60 * 60, 
    blockDuration: rate_limiters?.initPasswordResetLimiters?.ipLimiter.blockDuration ?? 4 * 60 * 60,
    inMemoryBlockDuration: rate_limiters?.initPasswordResetLimiters?.ipLimiter.inMemoryBlockDuration ?? 4 * 60 * 60 
  }); 
  
  const emailLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: rate_limiters?.initPasswordResetLimiters?.emailLimiter.inMemoryBlockOnConsumed ?? 5,
    tableName: 'password_reset',
    keyPrefix: 'email_limiter',
    points: rate_limiters?.initPasswordResetLimiters?.emailLimiter.points ?? 5,
    duration: rate_limiters?.initPasswordResetLimiters?.emailLimiter.duration ?? 24 * 60 * 60, 
    blockDuration: rate_limiters?.initPasswordResetLimiters?.emailLimiter.blockDuration ?? 4 * 60 * 60,
    inMemoryBlockDuration: rate_limiters?.initPasswordResetLimiters?.emailLimiter.inMemoryBlockDuration ?? 4 * 60 * 60 
  }); 

  return {
    uniLimiter: unionLimiter([limit, longLimiter ], false),
    ipLimiter,
    emailLimiter,
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
  const { uniLimiter, ipLimiter, emailLimiter } = ensureLimiter();
  return {uniLimiter, ipLimiter, emailLimiter };
}

export function resetLimitersUni(key: string) {
  return ensureLimiter().resetUnionLimiter(key)
}
