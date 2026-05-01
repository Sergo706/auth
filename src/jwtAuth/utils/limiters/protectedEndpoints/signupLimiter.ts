import { poolForLibrary } from '../../../config/configuration.js';
import { BlockableUnion, makeRateLimiter, unionLimiter} from '../rateLimit.js'
import { getConfiguration } from '../../../config/configuration.js';
import { RateLimiterMemory, RateLimiterMySQL, RLWrapperBlackAndWhite } from 'rate-limiter-flexible';


interface LimiterBundle {
  uniLimiterIp: BlockableUnion | RLWrapperBlackAndWhite;
  uniLimiterComposite: BlockableUnion | RLWrapperBlackAndWhite;
  emailLimiter: RateLimiterMySQL | RateLimiterMemory;
  resetUnionIpLimiter(key: string): Promise<void>;
  resetUnionCompostieLimiter(key: string): Promise<void>;
}

let limiter: LimiterBundle | null;

function buildLimiter(): LimiterBundle { 
  const { store, rate_limiters } = getConfiguration();
  const pool = poolForLibrary() as unknown as any;
  const limiterConfig = rate_limiters!.signupLimiters!.unionLimiters.uniLimiterIp;
  const limiterConfigComposite = rate_limiters!.signupLimiters!.unionLimiters.uniLimiterComposite;

  const ipLimit = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig?.ipLimit.inMemoryBlockOnConsumed ?? 2,
    keyPrefix: 'signups_brute',
    points: limiterConfig?.ipLimit.points ?? 2,
    tableName: 'signups',
    duration: limiterConfig?.ipLimit.duration ?? 1, 
    blockDuration: limiterConfig?.ipLimit.blockDuration ?? 900,  
    inMemoryBlockDuration: limiterConfig?.ipLimit.inMemoryBlockDuration ?? 900 
  });
  
  const slowIpLimit = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig?.slowIpLimit.inMemoryBlockOnConsumed ?? 5,
    keyPrefix: 'signups_slow',
    points: limiterConfig?.slowIpLimit.points ?? 5,
    tableName: 'signups',
    duration: limiterConfig?.slowIpLimit.duration ?? 60 * 30, 
    blockDuration: limiterConfig?.slowIpLimit.blockDuration ?? 60 * 15,  
    inMemoryBlockDuration: limiterConfig?.slowIpLimit.inMemoryBlockDuration ?? 60 * 15 
  });
  
  
  const compositeKeyLimit = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed:  limiterConfigComposite?.compositeKeyLimit.inMemoryBlockOnConsumed ?? 1,
    keyPrefix: 'compositeKey_brute',
    points: limiterConfigComposite?.compositeKeyLimit.points ?? 1,
    tableName: 'signups',
    duration: limiterConfigComposite?.compositeKeyLimit.duration ?? 1, 
    blockDuration: limiterConfigComposite?.compositeKeyLimit.blockDuration ?? 1800,  
    inMemoryBlockDuration: limiterConfigComposite?.compositeKeyLimit.inMemoryBlockDuration ?? 1800 
  });
  
  const slowCompositeKeyLimit = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfigComposite?.slowCompositeKeyLimit.inMemoryBlockOnConsumed ?? 3,
    keyPrefix: 'compositeKey_slow',
    points: limiterConfigComposite?.slowCompositeKeyLimit.points ?? 3,
    tableName: 'signups',
    duration: limiterConfigComposite?.slowCompositeKeyLimit.duration ?? 60 * 60 * 24, 
    blockDuration: limiterConfigComposite?.slowCompositeKeyLimit.blockDuration ?? 60 * 60 * 24,  
    inMemoryBlockDuration: limiterConfigComposite?.slowCompositeKeyLimit.inMemoryBlockDuration ?? 60 * 60 * 24 
  });
  
  const emailLimit = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: rate_limiters!.signupLimiters!.emailLimit.inMemoryBlockOnConsumed ?? 3,
    keyPrefix: 'email',
    points: rate_limiters!.signupLimiters!.emailLimit.points ?? 3,
    tableName: 'signups',
    duration: rate_limiters!.signupLimiters!.emailLimit.duration ?? 60 * 60 * 24, 
    blockDuration: rate_limiters!.signupLimiters!.emailLimit.blockDuration ?? 60 * 60 * 24,  
    inMemoryBlockDuration: rate_limiters!.signupLimiters!.emailLimit.inMemoryBlockDuration ?? 60 * 60 * 24 
  });

   return {
      uniLimiterIp: unionLimiter([ipLimit, slowIpLimit], false),
      uniLimiterComposite: unionLimiter([compositeKeyLimit, slowCompositeKeyLimit ], false),
      emailLimiter: emailLimit,
      resetUnionIpLimiter: async (key: string) => {
      await Promise.all([
        ipLimit.delete(key),        
        slowIpLimit.delete(key), 
      ]);
    },
      resetUnionCompostieLimiter: async (key: string) => {
      await Promise.all([
        compositeKeyLimit.delete(key),        
        slowCompositeKeyLimit.delete(key), 
      ]);
    },
   }

}



function ensureLimiter(): LimiterBundle {
  if (!limiter) {
    limiter = buildLimiter();
  }
  return limiter;
}

export function getLimiters() {
  const { uniLimiterIp, uniLimiterComposite, emailLimiter } = ensureLimiter();
  return { uniLimiterIp, uniLimiterComposite, emailLimiter };
}

export function resetLimitersUni() {
  return {
    resetUnionIpLimiter:(key: string) => {
      ensureLimiter().resetUnionIpLimiter(key)
    },
    resetUnionCompostieLimiter: (key: string) => {
       ensureLimiter().resetUnionCompostieLimiter(key)
    } 
  }
}

