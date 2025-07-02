import { poolForLibary } from '../../../config/dbConnection.js';
import { config } from '../../../config/secret.js';
import {makeRateLimiter, unionLimiter} from '../rateLimit.js'


const accessTokenBrute = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 2,
  keyPrefix: 'tokens_access_token_brute',
  points: 2,
  tableName: 'tokens',
  duration: 1, 
  blockDuration: 1800,  
  inMemoryBlockDuration: 1800 
});

const accessTokenSlow = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 3,
  keyPrefix: 'tokens_access_token_slow',
  points: 3,
  tableName: 'tokens',
  duration: 60 * 10, 
  blockDuration: 60 * 60,  
  inMemoryBlockDuration: 60 * 60 
});


const refreshTokenBrute = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 2,
  keyPrefix: 'refreshToken_brute',
  points: 2,
  tableName: 'tokens',
  duration: 1, 
  blockDuration: 1800,  
  inMemoryBlockDuration: 1800 
});

const refreshTokenSlow = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 4,
  keyPrefix: 'refreshToken_slow',
  points: 4,
  tableName: 'tokens',
  duration: 60 * 60 * 12, 
  blockDuration: 60 * 60 * 12,  
  inMemoryBlockDuration: 60 * 60 * 12 
});


export const refreshTokenLimiter = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 3,
  keyPrefix: 'refreshTokenLimiter_slow',
  points: 3,
  tableName: 'tokens',
  duration: 60 * 60 * 12, 
  blockDuration: 60 * 60 * 15,
  inMemoryBlockDuration: 60 * 60 * 15
});

export const blackList = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 45,
  tableName: 'tokens_limiter',
  keyPrefix: 'tokens_limiter_black',
  points: 20,
  duration: 24 * 60 * 60, 
  blockDuration: 3 * 24 * 60 * 60,
  inMemoryBlockDuration: 3 * 24 * 60 * 60 
}); 

export const refreshAccessTokenLimiter = unionLimiter([accessTokenBrute, accessTokenSlow ], false);
export const refreshTokenLimiterUnion = unionLimiter([refreshTokenBrute, refreshTokenSlow], false);

