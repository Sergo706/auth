import { LRUCache } from "lru-cache";
import { getConfiguration } from "../config/configuration.js";

export interface TokenCacheEntry {
    jti: string,
    visitorId: number,
    userId: number,
    roles?: string[],
    valid: boolean
}

let cache: LRUCache<string, TokenCacheEntry> | undefined;

export function tokenCache(): LRUCache<string, TokenCacheEntry> {
 if (cache) return cache;

const { access_tokens } = getConfiguration().jwt;

 cache = new LRUCache<string, TokenCacheEntry>({
   max: access_tokens.maxCacheEntries ?? 500, 
   ttl: access_tokens.expiresInMs ? access_tokens.expiresInMs : 15 * 60 * 1000
 });
 return cache;
}