import { poolForLibrary } from '../../../config/configuration.js';
import { BlockableUnion, makeRateLimiter, unionLimiter} from '../rateLimit.js'
import { getConfiguration } from '../../../config/configuration.js';
import { RateLimiterMemory, RateLimiterMySQL, RLWrapperBlackAndWhite } from 'rate-limiter-flexible';



interface LimiterBundle {
  refreshAccessTokenLimiter: BlockableUnion | RLWrapperBlackAndWhite;
  refreshTokenLimiterUnion: BlockableUnion | RLWrapperBlackAndWhite;
  refreshTokenLimiter: RateLimiterMemory | RateLimiterMySQL;
  blackList: RateLimiterMemory | RateLimiterMySQL;
}

let limiter: LimiterBundle | null;

function buildLimiter(): LimiterBundle { 
  const { store, rate_limiters } = getConfiguration();
  const pool = poolForLibrary() as unknown as any;
  const limiterConfig = rate_limiters?.tokenLimiters?.unionLimiters;

  const accessTokenBrute = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig?.refreshAccessTokenLimiter.accessTokenBrute.inMemoryBlockOnConsumed ?? 2,
    keyPrefix: 'tokens_access_token_brute',
    points: limiterConfig?.refreshAccessTokenLimiter.accessTokenBrute.points ?? 2,
    tableName: 'tokens',
    duration: limiterConfig?.refreshAccessTokenLimiter.accessTokenBrute.duration ?? 1, 
    blockDuration: limiterConfig?.refreshAccessTokenLimiter.accessTokenBrute.blockDuration ?? 1800,  
    inMemoryBlockDuration: limiterConfig?.refreshAccessTokenLimiter.accessTokenBrute.inMemoryBlockDuration ?? 1800 
  });
  
  const accessTokenSlow = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig?.refreshAccessTokenLimiter.accessTokenSlow.inMemoryBlockOnConsumed ?? 3,
    keyPrefix: 'tokens_access_token_slow',
    points: limiterConfig?.refreshAccessTokenLimiter.accessTokenSlow.points ?? 3,
    tableName: 'tokens',
    duration: limiterConfig?.refreshAccessTokenLimiter.accessTokenSlow.duration ?? 60 * 10, 
    blockDuration: limiterConfig?.refreshAccessTokenLimiter.accessTokenSlow.blockDuration ?? 60 * 60,  
    inMemoryBlockDuration: limiterConfig?.refreshAccessTokenLimiter.accessTokenSlow.inMemoryBlockDuration ?? 60 * 60 
  });
  
  
  const refreshTokenBrute = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig?.refreshTokenLimiterUnion.refreshTokenBrute.inMemoryBlockOnConsumed ?? 2,
    keyPrefix: 'refreshToken_brute',
    points: limiterConfig?.refreshTokenLimiterUnion.refreshTokenBrute.points ?? 2,
    tableName: 'tokens',
    duration: limiterConfig?.refreshTokenLimiterUnion.refreshTokenBrute.duration ?? 1, 
    blockDuration: limiterConfig?.refreshTokenLimiterUnion.refreshTokenBrute.blockDuration ?? 1800,  
    inMemoryBlockDuration: limiterConfig?.refreshTokenLimiterUnion.refreshTokenBrute.inMemoryBlockDuration ?? 1800 
  });
  
  const refreshTokenSlow = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig?.refreshTokenLimiterUnion.refreshTokenSlow.inMemoryBlockOnConsumed ?? 4,
    keyPrefix: 'refreshToken_slow',
    points: limiterConfig?.refreshTokenLimiterUnion.refreshTokenSlow.points ?? 4,
    tableName: 'tokens',
    duration: limiterConfig?.refreshTokenLimiterUnion.refreshTokenSlow.duration ?? 60 * 60 * 12, 
    blockDuration: limiterConfig?.refreshTokenLimiterUnion.refreshTokenSlow.blockDuration ?? 60 * 60 * 12,  
    inMemoryBlockDuration: limiterConfig?.refreshTokenLimiterUnion.refreshTokenSlow.inMemoryBlockDuration ?? 60 * 60 * 12 
  });
  
  
  const refreshTokenLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: rate_limiters?.tokenLimiters?.refreshTokenLimiter.inMemoryBlockOnConsumed ?? 3,
    keyPrefix: 'refreshTokenLimiter_slow',
    points: rate_limiters?.tokenLimiters?.refreshTokenLimiter.points ?? 3,
    tableName: 'tokens',
    duration: rate_limiters?.tokenLimiters?.refreshTokenLimiter.duration ?? 60 * 60 * 12, 
    blockDuration: rate_limiters?.tokenLimiters?.refreshTokenLimiter.blockDuration ?? 60 * 60 * 15,
    inMemoryBlockDuration: rate_limiters?.tokenLimiters?.refreshTokenLimiter.inMemoryBlockDuration ?? 60 * 60 * 15
  });
  
  const blackList = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: 45,
    tableName: 'tokens_limiter',
    keyPrefix: 'tokens_limiter_black',
    points: 20,
    duration: 24 * 60 * 60, 
    blockDuration: 3 * 24 * 60 * 60,
    inMemoryBlockDuration: 3 * 24 * 60 * 60 
  }); 
 
  return {
    refreshAccessTokenLimiter: unionLimiter([accessTokenBrute, accessTokenSlow ], false),
    refreshTokenLimiterUnion: unionLimiter([refreshTokenBrute, refreshTokenSlow], false),
    refreshTokenLimiter,
    blackList
  }

}

function ensureLimiter(): LimiterBundle {
  if (!limiter) {
    limiter = buildLimiter();
  }
  return limiter;
}

export function getLimiters() {
  const { refreshAccessTokenLimiter, refreshTokenLimiterUnion, refreshTokenLimiter, blackList } = ensureLimiter();
  return {refreshAccessTokenLimiter, refreshTokenLimiterUnion, refreshTokenLimiter, blackList};
}

