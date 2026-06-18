import { LRUCache } from 'lru-cache';
import { poolForLibrary } from '../../../config/configuration.js';
import { getConfiguration } from '../../../config/configuration.js';
import {BlockableUnion, makeRateLimiter, unionLimiter} from '../rateLimit.js'
import { RateLimiterMemory, RateLimiterMySQL, RLWrapperBlackAndWhite } from 'rate-limiter-flexible';
import { makeConsecutiveCache } from '../utils/consecutiveCache.js';

interface Cache<T extends {}> {
  newTokenCreationLimiter: LRUCache<string, T>;
  revokeTokensLimiter: LRUCache<string, T>;
  getMetadataTokenLimiter: LRUCache<string, T>;
  rotationRateLimiter: LRUCache<string, T>;
  ipRestrictionUpdate: LRUCache<string, T>;
  privilegeUpdate: LRUCache<string, T>;
  consumptionRateLimiter: LRUCache<string, T>;
  generalUnionLimiter: LRUCache<string, T>;
}

interface LimiterBundle<T extends {}> {
  newTokenCreationLimiter: RateLimiterMySQL | RateLimiterMemory;
  revokeTokensLimiter: RateLimiterMySQL | RateLimiterMemory;
  getMetadataTokenLimiter: RateLimiterMySQL | RateLimiterMemory;
  rotationRateLimiter: RateLimiterMySQL | RateLimiterMemory;
  ipRestrictionUpdate: RateLimiterMySQL | RateLimiterMemory;
  privilegeUpdate: RateLimiterMySQL | RateLimiterMemory;
  consumptionRateLimiter: RateLimiterMySQL | RateLimiterMemory;
  generalUnionLimiter: BlockableUnion | RLWrapperBlackAndWhite;
  resetLimitersUni(key: string): Promise<void>;
  cache: Cache<T>
}

let limiter: LimiterBundle<{countData:number}> | null = null;

function buildLimiters(): LimiterBundle<{countData:number}> {
  const { store, rate_limiters } = getConfiguration();
  const pool = poolForLibrary() as unknown as any;

  const limiterConfig = rate_limiters.apiTokensLimiters.operationRateLimits;
  const consumptionConfig = rate_limiters.apiTokensLimiters.consumptionRateLimiter;
  const unionLimitersConfig = rate_limiters.apiTokensLimiters.generalUnionLimiter;

  const generalUnionLimiterBurst = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType: 'mysql2',
    keyPrefix: 'general_union_burst',
    inMemoryBlockOnConsumed: unionLimitersConfig.burstLimiter.inMemoryBlockOnConsumed,
    points: unionLimitersConfig.burstLimiter.points,
    tableName: 'api_tokens_rate_limiters',
    duration: unionLimitersConfig.burstLimiter.duration, 
    blockDuration: unionLimitersConfig.burstLimiter.blockDuration, // block for 15 min, if more then 1 req in a second 
    inMemoryBlockDuration: unionLimitersConfig.burstLimiter.inMemoryBlockDuration
  })

  const generalUnionLimiterSlow = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType: 'mysql2',
    keyPrefix: 'general_union_slow',
    inMemoryBlockOnConsumed: unionLimitersConfig.slowLimiter.inMemoryBlockOnConsumed,
    points: unionLimitersConfig.slowLimiter.points,
    tableName: 'api_tokens_rate_limiters',
    duration: unionLimitersConfig.slowLimiter.duration, 
    blockDuration: unionLimitersConfig.slowLimiter.blockDuration, // block for 1 hour, if more then 50 req in a minute 
    inMemoryBlockDuration: unionLimitersConfig.slowLimiter.inMemoryBlockDuration
  })

  const newTokenCreation = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType: 'mysql2',
    keyPrefix: 'new_token_creation',
    inMemoryBlockOnConsumed: limiterConfig.newTokenCreationLimiter.inMemoryBlockOnConsumed,
    points: limiterConfig.newTokenCreationLimiter.points,
    tableName: 'api_tokens_rate_limiters',
    duration: limiterConfig.newTokenCreationLimiter.duration, // reset points after 10min
    blockDuration: limiterConfig.newTokenCreationLimiter.blockDuration, // block for 1 hours after points are consumed
    inMemoryBlockDuration: limiterConfig.newTokenCreationLimiter.inMemoryBlockDuration
  });

  const revokeLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType: 'mysql2',
    keyPrefix: 'revoke_token',
    inMemoryBlockOnConsumed: limiterConfig.revokeTokensLimiter.inMemoryBlockOnConsumed,
    points: limiterConfig.revokeTokensLimiter.points,
    tableName: 'api_tokens_rate_limiters',
    duration: limiterConfig.revokeTokensLimiter.duration, // reset points after 10min
    blockDuration: limiterConfig.revokeTokensLimiter.blockDuration, 
    inMemoryBlockDuration: limiterConfig.revokeTokensLimiter.inMemoryBlockDuration
  });

  const getMetadataLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType: 'mysql2',
    keyPrefix: 'get_metadata_token',
    inMemoryBlockOnConsumed: limiterConfig.getMetadataTokenLimiter.inMemoryBlockOnConsumed,
    points: limiterConfig.getMetadataTokenLimiter.points,
    tableName: 'api_tokens_rate_limiters',
    duration: limiterConfig.getMetadataTokenLimiter.duration, // reset every 2 sec
    blockDuration: limiterConfig.getMetadataTokenLimiter.blockDuration, // block for 30 min
    inMemoryBlockDuration: limiterConfig.getMetadataTokenLimiter.inMemoryBlockDuration
  });

  const rotationLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType: 'mysql2',
    keyPrefix: 'rotation_rate',
    inMemoryBlockOnConsumed: limiterConfig.rotationRateLimiter.inMemoryBlockOnConsumed,
    points: limiterConfig.rotationRateLimiter.points,
    tableName: 'api_tokens_rate_limiters',
    duration: limiterConfig.rotationRateLimiter.duration,
    blockDuration: limiterConfig.rotationRateLimiter.blockDuration,
    inMemoryBlockDuration: limiterConfig.rotationRateLimiter.inMemoryBlockDuration
  });

  const ipRestrictionLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType: 'mysql2',
    keyPrefix: 'ip_restriction_update',
    inMemoryBlockOnConsumed: limiterConfig.ipRestrictionUpdate.inMemoryBlockOnConsumed,
    points: limiterConfig.ipRestrictionUpdate.points,
    tableName: 'api_tokens_rate_limiters',
    duration: limiterConfig.ipRestrictionUpdate.duration,
    blockDuration: limiterConfig.ipRestrictionUpdate.blockDuration, // block for 30 min after 5 updates in 10 min
    inMemoryBlockDuration: limiterConfig.ipRestrictionUpdate.inMemoryBlockDuration
  });

  const privilegeUpdateLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType: 'mysql2',
    keyPrefix: 'privilege_update',
    inMemoryBlockOnConsumed: limiterConfig.privilegeUpdate.inMemoryBlockOnConsumed,
    points: limiterConfig.privilegeUpdate.points,
    tableName: 'api_tokens_rate_limiters',
    duration: limiterConfig.privilegeUpdate.duration,
    blockDuration: limiterConfig.privilegeUpdate.blockDuration,
    inMemoryBlockDuration: limiterConfig.privilegeUpdate.inMemoryBlockDuration
  });

  const consumptionLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType: 'mysql2',
    keyPrefix: 'consumption_rate',
    inMemoryBlockOnConsumed: consumptionConfig.inMemoryBlockOnConsumed,
    points: consumptionConfig.points,
    tableName: 'api_tokens_rate_limiters',
    duration: consumptionConfig.duration,
    blockDuration: consumptionConfig.blockDuration, // block for 1 hour after 10 req in 1 min
    inMemoryBlockDuration: consumptionConfig.inMemoryBlockDuration
  });

  return {
    newTokenCreationLimiter: newTokenCreation,
    revokeTokensLimiter: revokeLimiter,
    getMetadataTokenLimiter: getMetadataLimiter,
    rotationRateLimiter: rotationLimiter,
    ipRestrictionUpdate: ipRestrictionLimiter,
    privilegeUpdate: privilegeUpdateLimiter,
    consumptionRateLimiter: consumptionLimiter,
    generalUnionLimiter: unionLimiter([generalUnionLimiterBurst, generalUnionLimiterSlow], false),
    cache: {
        newTokenCreationLimiter: makeConsecutiveCache<{countData:number}>(
            2000, 
            limiterConfig.newTokenCreationLimiter.duration * 1000
        ),
        revokeTokensLimiter: makeConsecutiveCache<{countData:number}>( 
            2000, 
            limiterConfig.revokeTokensLimiter.duration * 1000
        ),
        getMetadataTokenLimiter: makeConsecutiveCache<{countData:number}>(
            2000,
            limiterConfig.getMetadataTokenLimiter.duration * 1000
        ),
        rotationRateLimiter: makeConsecutiveCache<{countData:number}>(
            2000, 
            limiterConfig.rotationRateLimiter.duration * 1000
        ),

        ipRestrictionUpdate: makeConsecutiveCache<{countData:number}>(
            2000, 
            limiterConfig.ipRestrictionUpdate.duration * 1000
        ),   

        privilegeUpdate: makeConsecutiveCache<{countData:number}>(
            2000, 
            limiterConfig.privilegeUpdate.duration * 1000
        ),

        consumptionRateLimiter: makeConsecutiveCache<{countData:number}>(
            2000, 
            consumptionConfig.blockDuration * 1000
        ),      

        generalUnionLimiter: makeConsecutiveCache<{countData:number}>(
            2000, 
            unionLimitersConfig.slowLimiter.duration * 1000
        ),
    },
  resetLimitersUni: async (key: string) => {
  await Promise.all([
        generalUnionLimiterBurst.delete(key),        
        generalUnionLimiterSlow.delete(key), 
   ])
  }   
  };
}

function ensureLimiter(): LimiterBundle<{countData:number}> {
  if (!limiter) {
    limiter = buildLimiters();
  }
  return limiter;
}

     
export function getApiLimiters() {
  return ensureLimiter();
}

export function resetApiUnionLimiters(key: string) {
  return ensureLimiter().resetLimitersUni(key);
}
