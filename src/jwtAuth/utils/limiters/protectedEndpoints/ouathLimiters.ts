import { poolForLibary } from '../../../config/dbConnection.js';
import { config } from '../../../config/secret.js';
import {makeRateLimiter, unionLimiter} from '../rateLimit.js'



const ipLimiterBrute = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 1,
  keyPrefix: 'ouath_ip_brute',
  points: 1,
  tableName: 'ouath',
  duration: 1, 
  blockDuration: 60 * 5,  
  inMemoryBlockDuration: 60 * 5 
});

const ipLimiterSlow = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 25,
  keyPrefix: 'ouath_ip_slow',
  points: 25,
  tableName: 'ouath',
  duration: 60 * 60, 
  blockDuration: 60 * 30,  
  inMemoryBlockDuration: 60 * 30 
});

export const subLimiter = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 5,
  keyPrefix: 'ouath_sub',
  points: 5,
  tableName: 'ouath',
  duration: 60 * 5, 
  blockDuration: 60 * 15,  
  inMemoryBlockDuration: 60 * 15 
});

export const compositeKeyLimiter = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 3,
  keyPrefix: 'ouath_compositeKey',
  points: 3,
  tableName: 'ouath',
  duration: 60 * 10, 
  blockDuration: 60 * 15,  
  inMemoryBlockDuration: 60 * 15 
});


export const uniLimiter = unionLimiter([ipLimiterBrute, ipLimiterSlow ], false);