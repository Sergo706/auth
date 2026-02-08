import { LRUCache } from "lru-cache";
import { getConfiguration } from "../config/configuration.js";


export type CacheEntry<T extends Record<string, unknown> = Record<string, unknown>> = {
  visitor: number;
  subject: string;
  purpose: "PASSWORD_RESET" | "MFA" | string;
  jti: string;
  valid: boolean;
} & T;

let cache: LRUCache<string, CacheEntry<any>> | undefined;

export function magicLinksCache(): LRUCache<string, CacheEntry<any>> {
 if (cache) return cache;

const { magic_links } = getConfiguration(); 

 cache = new LRUCache<string, CacheEntry<any>>({
   max: magic_links.maxCacheEntries ?? 500, 
   ttl: magic_links.expiresInMs ? magic_links.expiresInMs : 15 * 60 * 1000
 });
 return cache;
}