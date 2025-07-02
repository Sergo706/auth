import { poolForLibary } from '../../../config/dbConnection.js';
import { config } from '../../../config/secret.js';
import {makeRateLimiter, unionLimiter} from '../rateLimit.js'


const limit = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 1,
  keyPrefix: 'tempPostRoutes_brute',
  points: 1,
  tableName: 'tempPostRoutes',
  duration: 1, 
  blockDuration: 1800,  
  inMemoryBlockDuration: 1800 
});

const slowLimit = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 5,
  keyPrefix: 'tempPostRoutes_slow',
  points: 5,
  tableName: 'tempPostRoutes',
  duration: 60 * 10, 
  blockDuration: 60 * 10,  
  inMemoryBlockDuration: 60 * 10 
});

export const ipLimit = makeRateLimiter(true, false, {
  dbName: config.db.name!,
  storeClient: poolForLibary as unknown as any,
  storeType  : 'mysql2',
  inMemoryBlockOnConsumed: 6,
  keyPrefix: 'tempPostRoutes_ip',
  points: 6,
  tableName: 'tempPostRoutes',
  duration: 60 * 10, 
  blockDuration: 60 * 10,  
  inMemoryBlockDuration: 60 * 10 
});



export const uniLimiter = unionLimiter([limit, slowLimit ], false);

export async function resetCompositeKey(key: string) {
  await Promise.all([
    limit.delete(key),        
    slowLimit.delete(key), 
  ]);
}
