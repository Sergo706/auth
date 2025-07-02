import { poolForLibary } from '../../../config/dbConnection.js';
import { config } from '../../../config/secret.js';
import {makeRateLimiter, unionLimiter} from '../rateLimit.js'


const limit = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 2,
  keyPrefix: 'link_verification_brute',
  points: 2,
  tableName: 'link_verification',
  duration: 1, 
  blockDuration: 60 * 15,  
  inMemoryBlockDuration: 60 * 15 
});

const slowLimit = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 30,
  keyPrefix: 'link_verification_slow',
  points: 30,
  tableName: 'link_verification',
  duration: 60 * 30, 
  blockDuration: 1800,  
  inMemoryBlockDuration: 1800 
});


export const uniLimiter = unionLimiter([limit, slowLimit ], false);

export async function resetLimitersUni(key: string) {
  await Promise.all([
    limit.delete(key),        
    slowLimit.delete(key),
  ]);
}
