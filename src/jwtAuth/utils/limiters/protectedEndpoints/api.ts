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

  const limiterConfig = rate_limiters?.apiTokensLimiters?.operationRateLimits;
  const consumptionConfig = rate_limiters?.apiTokensLimiters?.consumptionRateLimiter;
  const unionLimitersConfig = rate_limiters?.apiTokensLimiters?.generalUnionLimiter;

  const generalUnionLimiterBurst = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType: 'mysql2',
    keyPrefix: 'general_union_burst',
    inMemoryBlockOnConsumed: unionLimitersConfig?.burstLimiter?.inMemoryBlockOnConsumed ?? 1,
    points: unionLimitersConfig?.burstLimiter?.points ?? 1,
    tableName: 'api_tokens_rate_limiters',
    duration: unionLimitersConfig?.burstLimiter?.duration ?? 1, 
    blockDuration: unionLimitersConfig?.burstLimiter?.blockDuration ?? 60 * 15, // block for 15 min, if more then 1 req in a second 
    inMemoryBlockDuration: unionLimitersConfig?.burstLimiter?.inMemoryBlockDuration ?? 60 * 15
  })

  const generalUnionLimiterSlow = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType: 'mysql2',
    keyPrefix: 'general_union_slow',
    inMemoryBlockOnConsumed: unionLimitersConfig?.slowLimiter?.inMemoryBlockOnConsumed ?? 50,
    points: unionLimitersConfig?.slowLimiter?.points ?? 50,
    tableName: 'api_tokens_rate_limiters',
    duration: unionLimitersConfig?.slowLimiter?.duration ?? 60, 
    blockDuration: unionLimitersConfig?.slowLimiter?.blockDuration ?? 60 * 60, // block for 1 hour, if more then 50 req in a minute 
    inMemoryBlockDuration: unionLimitersConfig?.slowLimiter?.inMemoryBlockDuration ?? 60 * 60
  })

  const newTokenCreation = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType: 'mysql2',
    keyPrefix: 'new_token_creation',
    inMemoryBlockOnConsumed: limiterConfig?.newTokenCreationLimiter.inMemoryBlockOnConsumed ?? 5,
    points: limiterConfig?.newTokenCreationLimiter.points ?? 5,
    tableName: 'api_tokens_rate_limiters',
    duration: limiterConfig?.newTokenCreationLimiter.duration ?? 60 * 10, // reset points after 10min
    blockDuration: limiterConfig?.newTokenCreationLimiter.blockDuration ?? 60 * 60, // block for 1 hours after points are consumed
    inMemoryBlockDuration: limiterConfig?.newTokenCreationLimiter.inMemoryBlockDuration ?? 60 * 60
  });

  const revokeLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType: 'mysql2',
    keyPrefix: 'revoke_token',
    inMemoryBlockOnConsumed: limiterConfig?.revokeTokensLimiter.inMemoryBlockOnConsumed ?? 5,
    points: limiterConfig?.revokeTokensLimiter.points ?? 5,
    tableName: 'api_tokens_rate_limiters',
    duration: limiterConfig?.revokeTokensLimiter.duration ?? 60 * 10, // reset points after 10min
    blockDuration: limiterConfig?.revokeTokensLimiter.blockDuration ?? 60 * 60 * 2, 
    inMemoryBlockDuration: limiterConfig?.revokeTokensLimiter.inMemoryBlockDuration ?? 60 * 60 * 2
  });

  const getMetadataLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType: 'mysql2',
    keyPrefix: 'get_metadata_token',
    inMemoryBlockOnConsumed: limiterConfig?.getMetadataTokenLimiter.inMemoryBlockOnConsumed ?? 20,
    points: limiterConfig?.getMetadataTokenLimiter.points ?? 20,
    tableName: 'api_tokens_rate_limiters',
    duration: limiterConfig?.getMetadataTokenLimiter.duration ?? 2, // reset every 2 sec
    blockDuration: limiterConfig?.getMetadataTokenLimiter.blockDuration ?? 60 * 30, // block for 30 min
    inMemoryBlockDuration: limiterConfig?.getMetadataTokenLimiter.inMemoryBlockDuration ?? 60 * 30
  });

  const rotationLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType: 'mysql2',
    keyPrefix: 'rotation_rate',
    inMemoryBlockOnConsumed: limiterConfig?.rotationRateLimiter.inMemoryBlockOnConsumed ?? 5,
    points: limiterConfig?.rotationRateLimiter.points ?? 5,
    tableName: 'api_tokens_rate_limiters',
    duration: limiterConfig?.rotationRateLimiter.duration ?? 60 * 10,
    blockDuration: limiterConfig?.rotationRateLimiter.blockDuration ?? 60 * 60 * 2,
    inMemoryBlockDuration: limiterConfig?.rotationRateLimiter.inMemoryBlockDuration ?? 60 * 60 * 2
  });

  const ipRestrictionLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType: 'mysql2',
    keyPrefix: 'ip_restriction_update',
    inMemoryBlockOnConsumed: limiterConfig?.ipRestrictionUpdate.inMemoryBlockOnConsumed ?? 5,
    points: limiterConfig?.ipRestrictionUpdate.points ?? 5,
    tableName: 'api_tokens_rate_limiters',
    duration: limiterConfig?.ipRestrictionUpdate.duration ?? 60 * 10,
    blockDuration: limiterConfig?.ipRestrictionUpdate.blockDuration ?? 60 * 30, // block for 30 min after 5 updates in 10 min
    inMemoryBlockDuration: limiterConfig?.ipRestrictionUpdate.inMemoryBlockDuration ?? 60 * 30
  });

  const privilegeUpdateLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType: 'mysql2',
    keyPrefix: 'privilege_update',
    inMemoryBlockOnConsumed: limiterConfig?.privilegeUpdate.inMemoryBlockOnConsumed ?? 5,
    points: limiterConfig?.privilegeUpdate.points ?? 5,
    tableName: 'api_tokens_rate_limiters',
    duration: limiterConfig?.privilegeUpdate.duration ?? 60 * 10,
    blockDuration: limiterConfig?.privilegeUpdate.blockDuration ?? 60 * 30,
    inMemoryBlockDuration: limiterConfig?.privilegeUpdate.inMemoryBlockDuration ?? 60 * 30
  });

  const consumptionLimiter = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType: 'mysql2',
    keyPrefix: 'consumption_rate',
    inMemoryBlockOnConsumed: consumptionConfig?.inMemoryBlockDuration ?? 10,
    points: consumptionConfig?.points ?? 10,
    tableName: 'api_tokens_rate_limiters',
    duration: consumptionConfig?.duration ?? 60,
    blockDuration: consumptionConfig?.blockDuration ?? 60 * 60, // block for 1 hour after 10 req in 1 min
    inMemoryBlockDuration: consumptionConfig?.inMemoryBlockDuration ?? 60 * 60
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
            limiterConfig?.newTokenCreationLimiter.duration ? limiterConfig?.newTokenCreationLimiter.duration * 1000 : 
            1000 * 60 * 10
        ),
        revokeTokensLimiter: makeConsecutiveCache<{countData:number}>( 
            2000, 
            limiterConfig?.revokeTokensLimiter.duration ? limiterConfig?.revokeTokensLimiter.duration * 1000 :
            1000 * 60 * 10
        ),
        getMetadataTokenLimiter: makeConsecutiveCache<{countData:number}>(
            2000,
            limiterConfig?.getMetadataTokenLimiter.duration ? limiterConfig?.getMetadataTokenLimiter.duration * 1000 :
            1000 * 2 
        ),
        rotationRateLimiter: makeConsecutiveCache<{countData:number}>(
            2000, 
            limiterConfig?.rotationRateLimiter.duration ? limiterConfig?.rotationRateLimiter.duration * 1000 : 
            1000 * 60 * 10
        ),

        ipRestrictionUpdate: makeConsecutiveCache<{countData:number}>(
            2000, 
            limiterConfig?.ipRestrictionUpdate.duration ? limiterConfig?.ipRestrictionUpdate.duration * 1000 : 
            1000 * 60 * 10
        ),   

        privilegeUpdate: makeConsecutiveCache<{countData:number}>(
            2000, 
            limiterConfig?.privilegeUpdate.duration ? limiterConfig?.privilegeUpdate.duration * 1000 : 
            1000 * 60 * 10
        ),

        consumptionRateLimiter: makeConsecutiveCache<{countData:number}>(
            2000, 
            consumptionConfig?.blockDuration ? consumptionConfig?.blockDuration * 1000 : 
            1000 * 60
        ),      

        generalUnionLimiter: makeConsecutiveCache<{countData:number}>(
            2000, 
            unionLimitersConfig?.slowLimiter?.duration ? unionLimitersConfig?.slowLimiter?.duration * 1000 : 
            1000 * 60
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
