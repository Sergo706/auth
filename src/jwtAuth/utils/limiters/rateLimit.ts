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
 * Limiters factory.
 * @param sql if true, a mysql limiter is returned, false for memory limiter.
 * @param settings the libary configuration object with the next interface
 * @interface RateLimitSql
 * @interface RateLimitMermory
 * @param BlackWhiteList controll whenever to wrap the limiter in the libary BlackAndWhite list
 * @returns MySql limiter or a memory limiter with optionally in a black/white list
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
* Build a union of limiters and (optionally) wrap it with a black/white list.
* @param limiters an array of limiters produced via makeRateLimiter() function.
* @param blackWhiteList wrap it with a black/white list.
* @returns RateLimiterUnion or RateLimiterUnion wrapped in RLWrapperBlackAndWhite
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