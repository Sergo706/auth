import { LRUCache } from "lru-cache";

export interface AnomaliesCache {
    anomalyType: string,
    canaryCookie: string
    visitorId?: string
    userId?: number
    resolved: boolean;
    resolvable: boolean;
}

let cache: LRUCache<string, AnomaliesCache> | undefined;

export function anomaliesCache(): LRUCache<string, AnomaliesCache> | undefined {
  if (cache) return cache;

  cache = new LRUCache<string, AnomaliesCache, unknown>({
        max: 2000,
        ttl: 1000 * 60 * 60 * 2
  });
  
  return cache;
}   
