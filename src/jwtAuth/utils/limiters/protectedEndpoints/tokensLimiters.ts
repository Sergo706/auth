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
  const limiterConfig = rate_limiters.tokenLimiters.unionLimiters;

  const accessTokenBrute = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig.refreshAccessTokenLimiter.accessTokenBrute.inMemoryBlockOnConsumed,
    keyPrefix: 'tokens_access_token_brute',
    points: limiterConfig.refreshAccessTokenLimiter.accessTokenBrute.points,
    tableName: 'tokens',
    duration: limiterConfig.refreshAccessTokenLimiter.accessTokenBrute.duration, 
    blockDuration: limiterConfig.refreshAccessTokenLimiter.accessTokenBrute.blockDuration,  
    inMemoryBlockDuration: limiterConfig.refreshAccessTokenLimiter.accessTokenBrute.inMemoryBlockDuration 
  });
  
  const accessTokenSlow = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig.refreshAccessTokenLimiter.accessTokenSlow.inMemoryBlockOnConsumed,
    keyPrefix: 'tokens_access_token_slow',
    points: limiterConfig.refreshAccessTokenLimiter.accessTokenSlow.points,
    tableName: 'tokens',
    duration: limiterConfig.refreshAccessTokenLimiter.accessTokenSlow.duration, 
    blockDuration: limiterConfig.refreshAccessTokenLimiter.accessTokenSlow.blockDuration,  
    inMemoryBlockDuration: limiterConfig.refreshAccessTokenLimiter.accessTokenSlow.inMemoryBlockDuration 
  });
  
  
  const refreshTokenBrute = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig.refreshTokenLimiterUnion.refreshTokenBrute.inMemoryBlockOnConsumed,
    keyPrefix: 'refreshToken_brute',
    points: limiterConfig.refreshTokenLimiterUnion.refreshTokenBrute.points,
    tableName: 'tokens',
    duration: limiterConfig.refreshTokenLimiterUnion.refreshTokenBrute.duration, 
    blockDuration: limiterConfig.refreshTokenLimiterUnion.refreshTokenBrute.blockDuration,  
    inMemoryBlockDuration: limiterConfig.refreshTokenLimiterUnion.refreshTokenBrute.inMemoryBlockDuration 
  });
  
  const refreshTokenSlow = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig.refreshTokenLimiterUnion.refreshTokenSlow.inMemoryBlockOnConsumed,
    keyPrefix: 'refreshToken_slow',
    points: limiterConfig.refreshTokenLimiterUnion.refreshTokenSlow.points,
    tableName: 'tokens',
    duration: limiterConfig.refreshTokenLimiterUnion.refreshTokenSlow.duration, 
    blockDuration: limiterConfig.refreshTokenLimiterUnion.refreshTokenSlow.blockDuration,  
    inMemoryBlockDuration: limiterConfig.refreshTokenLimiterUnion.refreshTokenSlow.inMemoryBlockDuration 
  });
  
  
  const refreshTokenLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: rate_limiters.tokenLimiters.refreshTokenLimiter.inMemoryBlockOnConsumed,
    keyPrefix: 'refreshTokenLimiter_slow',
    points: rate_limiters.tokenLimiters.refreshTokenLimiter.points,
    tableName: 'tokens',
    duration: rate_limiters.tokenLimiters.refreshTokenLimiter.duration, 
    blockDuration: rate_limiters.tokenLimiters.refreshTokenLimiter.blockDuration,
    inMemoryBlockDuration: rate_limiters.tokenLimiters.refreshTokenLimiter.inMemoryBlockDuration
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

