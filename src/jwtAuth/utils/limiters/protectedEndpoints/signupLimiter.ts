import { poolForLibary } from '../../../config/dbConnection.js';
import { config } from '../../../config/secret.js';
import {makeRateLimiter, unionLimiter} from '../rateLimit.js'



const ipLimit = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 2,
  keyPrefix: 'signups_brute',
  points: 2,
  tableName: 'signups',
  duration: 1, 
  blockDuration: 900,  
  inMemoryBlockDuration: 900 
});

const slowIpLimit = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 5,
  keyPrefix: 'signups_slow',
  points: 5,
  tableName: 'signups',
  duration: 60 * 30, 
  blockDuration: 60 * 15,  
  inMemoryBlockDuration: 60 * 15 
});


const compositeKeyLimit = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 1,
  keyPrefix: 'compositeKey_brute',
  points: 1,
  tableName: 'signups',
  duration: 1, 
  blockDuration: 1800,  
  inMemoryBlockDuration: 1800 
});

const slowCompositeKeyLimit = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 3,
  keyPrefix: 'compositeKey_slow',
  points: 3,
  tableName: 'signups',
  duration: 60 * 60 * 24, 
  blockDuration: 60 * 60 * 24,  
  inMemoryBlockDuration: 60 * 60 * 24 
});

export const emailLimit = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 3,
  keyPrefix: 'email',
  points: 3,
  tableName: 'signups',
  duration: 60 * 60 * 24, 
  blockDuration: 60 * 60 * 24,  
  inMemoryBlockDuration: 60 * 60 * 24 
});



export const uniLimiterIp = unionLimiter([ipLimit, slowIpLimit], false);
export const uniLimiterComposite = unionLimiter([compositeKeyLimit, slowCompositeKeyLimit ], false);

export async function resetUnionIpLimiter(key: string) {
  await Promise.all([
    ipLimit.delete(key),        
    slowIpLimit.delete(key), 
  ]);
}

export async function resetUnionCompostieLimiter(key: string) {
  await Promise.all([
    compositeKeyLimit.delete(key),        
    slowCompositeKeyLimit.delete(key), 
  ]);
}
