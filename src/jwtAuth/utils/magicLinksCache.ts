import { LRUCache } from "lru-cache";
import { getConfiguration } from "../config/configuration.js";


export interface CacheEntry {
  visitor: number;
  subject: string;
  purpose: "PASSWORD_RESET" | "MFA";
  jti: string;
  valid: boolean;
}

let cache: LRUCache<string, CacheEntry> | undefined;

export function magicLinksCache(): LRUCache<string, CacheEntry> {
 if (cache) return cache;

const { magic_links } = getConfiguration(); 

 cache = new LRUCache<string, CacheEntry>({
   max: magic_links.maxCacheEntries ?? 500, 
   ttl: magic_links.expiresIn ? magic_links.expiresIn : 15 * 60 * 1000
 });
 return cache;
}