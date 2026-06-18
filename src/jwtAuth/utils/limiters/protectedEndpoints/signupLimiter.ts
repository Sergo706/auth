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
  const limiterConfig = rate_limiters.signupLimiters.unionLimiters.uniLimiterIp;
  const limiterConfigComposite = rate_limiters.signupLimiters.unionLimiters.uniLimiterComposite;

  const ipLimit = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig.ipLimit.inMemoryBlockOnConsumed,
    keyPrefix: 'signups_brute',
    points: limiterConfig.ipLimit.points,
    tableName: 'signups',
    duration: limiterConfig.ipLimit.duration, 
    blockDuration: limiterConfig.ipLimit.blockDuration,  
    inMemoryBlockDuration: limiterConfig.ipLimit.inMemoryBlockDuration 
  });
  
  const slowIpLimit = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfig.slowIpLimit.inMemoryBlockOnConsumed,
    keyPrefix: 'signups_slow',
    points: limiterConfig.slowIpLimit.points,
    tableName: 'signups',
    duration: limiterConfig.slowIpLimit.duration, 
    blockDuration: limiterConfig.slowIpLimit.blockDuration,  
    inMemoryBlockDuration: limiterConfig.slowIpLimit.inMemoryBlockDuration 
  });
  
  
  const compositeKeyLimit = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed:  limiterConfigComposite.compositeKeyLimit.inMemoryBlockOnConsumed,
    keyPrefix: 'compositeKey_brute',
    points: limiterConfigComposite.compositeKeyLimit.points,
    tableName: 'signups',
    duration: limiterConfigComposite.compositeKeyLimit.duration, 
    blockDuration: limiterConfigComposite.compositeKeyLimit.blockDuration,  
    inMemoryBlockDuration: limiterConfigComposite.compositeKeyLimit.inMemoryBlockDuration 
  });
  
  const slowCompositeKeyLimit = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: limiterConfigComposite.slowCompositeKeyLimit.inMemoryBlockOnConsumed,
    keyPrefix: 'compositeKey_slow',
    points: limiterConfigComposite.slowCompositeKeyLimit.points,
    tableName: 'signups',
    duration: limiterConfigComposite.slowCompositeKeyLimit.duration, 
    blockDuration: limiterConfigComposite.slowCompositeKeyLimit.blockDuration,  
    inMemoryBlockDuration: limiterConfigComposite.slowCompositeKeyLimit.inMemoryBlockDuration 
  });
  
  const emailLimit = makeRateLimiter(true, false, {
    dbName: store.rate_limiters_pool.dbName,
    storeClient: pool,
    storeType  : 'mysql2',
    inMemoryBlockOnConsumed: rate_limiters.signupLimiters.emailLimit.inMemoryBlockOnConsumed,
    keyPrefix: 'email',
    points: rate_limiters.signupLimiters.emailLimit.points,
    tableName: 'signups',
    duration: rate_limiters.signupLimiters.emailLimit.duration, 
    blockDuration: rate_limiters.signupLimiters.emailLimit.blockDuration,  
    inMemoryBlockDuration: rate_limiters.signupLimiters.emailLimit.inMemoryBlockDuration 
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

