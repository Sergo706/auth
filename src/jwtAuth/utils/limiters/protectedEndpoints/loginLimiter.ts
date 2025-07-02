import { poolForLibary } from '../../../config/dbConnection.js';
import { config } from '../../../config/secret.js';
import {makeRateLimiter, unionLimiter} from '../rateLimit.js'



const limit = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 1,
  keyPrefix: 'login',
  points: 1,
  tableName: 'login',
  duration: 1, 
  blockDuration: 1800,  
  inMemoryBlockDuration: 1800 
});

const longLimiter = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 5,
  tableName: 'login',
  keyPrefix: 'login_slow_down',
  points: 5,
  duration: 60 * 60, 
  blockDuration: 60 * 30,
  inMemoryBlockDuration: 60 * 30 
});

export const ipLimiter = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 15,
  tableName: 'login',
  keyPrefix: 'ip_limiter',
  points: 15,
  duration: 24 * 60 * 60, 
  blockDuration: 3 * 60 * 60,
  inMemoryBlockDuration: 3 * 60 * 60 
}); 

export const emailLimiter = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 5,
  tableName: 'login',
  keyPrefix: 'email_limiter',
  points: 5,
  duration: 24 * 60 * 60, 
  blockDuration: 5 * 60 * 60,
  inMemoryBlockDuration: 5 * 60 * 60 
}); 



export const uniLimiter = unionLimiter([limit, longLimiter ], false);

export async function resetLoginKey(key: string) {
  await Promise.all([
    limit.delete(key),        
    longLimiter.delete(key), 
    ipLimiter.delete(key),
    emailLimiter.delete(key),
  ]);
}

