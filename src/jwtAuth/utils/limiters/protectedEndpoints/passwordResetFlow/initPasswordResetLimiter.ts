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
  const limiterConfig = rate_limiters.initPasswordResetLimiters.unionLimiters;

  const limit = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig.limit.inMemoryBlockOnConsumed,
    keyPrefix: 'password_reset',
    points: limiterConfig.limit.points,
    tableName: 'password_reset',
    duration: limiterConfig.limit.duration, 
    blockDuration: limiterConfig.limit.blockDuration,  
    inMemoryBlockDuration: limiterConfig.limit.inMemoryBlockDuration 
  });
  
  const longLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig.longLimiter.inMemoryBlockOnConsumed,
    tableName: 'password_reset',
    keyPrefix: 'password_reset_slow_down',
    points: limiterConfig.longLimiter.points,
    duration: limiterConfig.longLimiter.duration, 
    blockDuration: limiterConfig.longLimiter.blockDuration,
    inMemoryBlockDuration: limiterConfig.longLimiter.inMemoryBlockDuration 
  });
  
  const ipLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: rate_limiters.initPasswordResetLimiters.ipLimiter.inMemoryBlockOnConsumed,
    tableName: 'password_reset',
    keyPrefix: 'ip_limiter',
    points: rate_limiters.initPasswordResetLimiters.ipLimiter.points,
    duration: rate_limiters.initPasswordResetLimiters.ipLimiter.duration, 
    blockDuration: rate_limiters.initPasswordResetLimiters.ipLimiter.blockDuration,
    inMemoryBlockDuration: rate_limiters.initPasswordResetLimiters.ipLimiter.inMemoryBlockDuration 
  }); 
  
  const emailLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: rate_limiters.initPasswordResetLimiters.emailLimiter.inMemoryBlockOnConsumed,
    tableName: 'password_reset',
    keyPrefix: 'email_limiter',
    points: rate_limiters.initPasswordResetLimiters.emailLimiter.points,
    duration: rate_limiters.initPasswordResetLimiters.emailLimiter.duration, 
    blockDuration: rate_limiters.initPasswordResetLimiters.emailLimiter.blockDuration,
    inMemoryBlockDuration: rate_limiters.initPasswordResetLimiters.emailLimiter.inMemoryBlockDuration 
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
