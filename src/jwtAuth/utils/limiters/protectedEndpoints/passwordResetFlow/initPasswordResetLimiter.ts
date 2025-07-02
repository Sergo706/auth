import { poolForLibary } from '../../../../config/dbConnection.js';
import { config } from '../../../../config/secret.js';
import {makeRateLimiter, unionLimiter} from '../../rateLimit.js'


const limit = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 1,
  keyPrefix: 'password_reset',
  points: 1,
  tableName: 'password_reset',
  duration: 1, 
  blockDuration: 1800,  
  inMemoryBlockDuration: 1800 
});

const longLimiter = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 4,
  tableName: 'password_reset',
  keyPrefix: 'password_reset_slow_down',
  points: 4,
  duration: 60 * 30, 
  blockDuration: 60 * 15,
  inMemoryBlockDuration: 60 * 15 
});

export const ipLimiter = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 5,
  tableName: 'password_reset',
  keyPrefix: 'ip_limiter',
  points: 5,
  duration: 24 * 60 * 60, 
  blockDuration: 4 * 60 * 60,
  inMemoryBlockDuration: 4 * 60 * 60 
}); 

export const emailLimiter = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 5,
  tableName: 'password_reset',
  keyPrefix: 'email_limiter',
  points: 5,
  duration: 24 * 60 * 60, 
  blockDuration: 4 * 60 * 60,
  inMemoryBlockDuration: 4 * 60 * 60 
}); 



export const uniLimiter = unionLimiter([limit, longLimiter ], false);

export async function resetUnionLimiter(key: string) {
  await Promise.all([
    limit.delete(key),        
    longLimiter.delete(key)
  ]);
}

