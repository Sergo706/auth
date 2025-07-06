import { Pool } from "mysql2";
import { RateLimiterMemory, RateLimiterMySQL, RateLimiterUnion, RLWrapperBlackAndWhite, RateLimiterAbstract, RateLimiterRes } from "rate-limiter-flexible";

export interface RateLimitMermory {
  keyPrefix: string;
  points: number;
  duration: number;
  blockDuration: number;
  inMemoryBlockDuration?:number;
}

export interface RateLimitSql extends RateLimitMermory {
  dbName: string;
  storeClient: Pool;
  inMemoryBlockOnConsumed?: number;
  tableName: string;
  storeType: 'mysql2',
}

export interface BlockableUnion extends RateLimiterUnion {
  block(key: string, durationSec?: number): Promise<RateLimiterRes[]>;
  delete(key: string): Promise<boolean[]>;
  keyPrefix: string[];
}
/**
 * @description
 * Create a new configurable rate limiter, either in-memory or backed by MySQL,
 * with optional black/white list wrapping.
 *
 * @function makeRateLimiter
 *
 * @param {boolean} sql
 *   If `true`, returns a MySQL-based limiter; if `false`, returns an in-memory limiter.
 * @param {boolean} blackWhiteList
 *   If `true`, wraps the limiter in a black/white list filter.
 * @param {Object} settings
 *   Configuration options for the limiter.
 * @param {string} [settings.dbName]
 *   Name of the MySQL database (only for SQL limiter).
 * @param {*} settings.storeClient
 *   Database client or connection pool (only for SQL limiter).
 * @param {string} [settings.storeType]
 *   Store type for SQL limiter (e.g. `'mysql2'`).
 * @param {number} [settings.inMemoryBlockOnConsumed]
 *   Number of points to consume before blocking in-memory (only for SQL limiter when wrapped).
 * @param {string} [settings.keyPrefix]
 *   Prefix for limiter keys (both types).
 * @param {number} settings.points
 *   Number of points (requests) allowed per duration.
 * @param {number} settings.duration
 *   Time window in seconds for point consumption.
 * @param {number} [settings.blockDuration]
 *   Duration in seconds to block on penalty (SQL limiter).
 * @param {number} [settings.inMemoryBlockDuration]
 *   Duration in seconds to block in-memory (when wrapped).
 *
 * @returns {
 *   import('rate-limiter-flexible').RateLimiterMySQL |
 *   import('rate-limiter-flexible').RateLimiterMemory |
 *   RLWrapperBlackAndWhite
 * }
 *   A MySQL or in-memory rate limiter, optionally wrapped in a black/white list.
 *
 * @see {@link ./jwtAuth/utils/limiters/rateLimit.js}
 * @see {@link https://github.com/animir/node-rate-limiter-flexible}
 *
 * @example
 * const limit = makeRateLimiter(
 *   true,                    // use MySQL
 *   false,                   // no black/white wrapper
 *   {
 *     dbName: 'app_db',
 *     storeClient: pool,
 *     storeType: 'mysql2',
 *     keyPrefix: 'login',
 *     points: 5,
 *     duration: 60,
 *     blockDuration: 1800
 *   }
 * );
 */
export function makeRateLimiter(sql: boolean, BlackWhiteList: boolean, settings: RateLimitMermory | RateLimitSql): 
RateLimiterMySQL | RateLimiterMemory | RLWrapperBlackAndWhite {

  let limiter;
  const { dbName, storeClient, inMemoryBlockOnConsumed, ...shared} = settings as RateLimitSql & RateLimitMermory;
  
  limiter = new RateLimiterMemory(shared)

  if (sql && "storeClient" in settings) {
     limiter = new RateLimiterMySQL(
      {
        insuranceLimiter: limiter,
      ...settings
      },  
      (err) => {
        if (err) console.error(`Sql Limiter ${settings.keyPrefix}, setup failed:`, err);
        console.log(`Sql Limiter ${settings.keyPrefix}, is ready!`);      
      }
    )
  }

  if (BlackWhiteList) {
    const lists = new RLWrapperBlackAndWhite({
    limiter: limiter,              
    whiteList: [],      
    blackList: [],       
    isWhiteListed: (ip) => /^10\.10\.10\.10$/.test(ip),  
    runActionAnyway: false,            
  });
   return lists;
  }
 return limiter;
}


 
class ExtendedRateLimiterUnion extends RateLimiterUnion implements BlockableUnion {
  constructor(
    private stores: Array<RateLimiterMemory | RateLimiterMySQL>
  ) {
    super(...stores);
  }
  keyPrefix = this.stores.map(k => k.keyPrefix);
  
  block(key: string, durationSec = 0): Promise<RateLimiterRes[]> {
    return Promise.all(this.stores.map(store => store.block(key, durationSec)));
  }
  
  delete(key: string): Promise<boolean[]> {
    return Promise.all(this.stores.map(store => store.delete(key)));
  }
}
/**
 * @description
 * Build a union of the provided rate limiters so they act as a single limiter, and optionally wrap it in a black/white list.
 *
 * @param {(import('rate-limiter-flexible').RateLimiterMySQL | import('rate-limiter-flexible').RateLimiterMemory)[]} limiters
 *   An array of limiter instances created via `makeRateLimiter()`.
 * @param {boolean} [blackWhiteList=false]
 *   If `true`, wraps the resulting union in an `RLWrapperBlackAndWhite` for black/white list filtering.
 *
 * @returns {BlockableUnion | RLWrapperBlackAndWhite}
 *   A `BlockableUnion` combining all provided limiters, or that union wrapped in an `RLWrapperBlackAndWhite`.
 *
 * @example
 * import { makeRateLimiter, unionLimiter } from './rateLimit.js';
 *
 * const limiter1 = makeRateLimiter(false, false, { points: 5, duration: 60 });
 * const limiter2 = makeRateLimiter(true, false, {
 *   dbName: 'app_db',
 *   storeClient: pool,
 *   storeType: 'mysql2',
 *   points: 10,
 *   duration: 60,
 * });
 *
 * // Combine them without black/white wrapping:
 * const union = unionLimiter([limiter1, limiter2]);
 *
 * // Combine and wrap in a black/white list:
 * const wrappedUnion = unionLimiter([limiter1, limiter2], true);
 */
export function unionLimiter(limiters: (RateLimiterMySQL | RateLimiterMemory)[], blackWhiteList: boolean): BlockableUnion | RLWrapperBlackAndWhite {

   let union = new ExtendedRateLimiterUnion(limiters);

    if (blackWhiteList) {
    const lists = new RLWrapperBlackAndWhite({
    limiter: union as unknown as RateLimiterAbstract,              
    whiteList: [],      
    blackList: [],       
    isWhiteListed: (ip) => /^10\.10\.10\.10$/.test(ip),  
    runActionAnyway: false,            
  });
    (lists as any).block = union.block.bind(union);
    (lists as any).delete = union.delete.bind(union);

    return lists;
  }
return union;
}   