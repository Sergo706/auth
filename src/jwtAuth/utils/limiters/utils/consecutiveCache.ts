import { LRUCache } from "lru-cache";


/**
 * @description
 * Creates a custom LRU cache with a fixed maximum size and entry TTL.
 *
 * @template T
 * @param {number} max - Maximum number of entries to store in the cache.
 * @param {number} ttl - Time-to-live for each entry (in milliseconds).
 *
 * @returns {import('lru-cache').LRUCache<string, T>}
 *   A new LRU cache instance providing `get`, `set`, `reset`, and `delete` methods.
 *
 * @see {@link ./jwtAuth/utils/limiters/utils/consecutiveCache.js}
 *
 * @example
 * const loginCache = makeConsecutiveCache<{ count: number }>(5, 60_000);
 * loginCache.set('user:123', { count: 1 });
 */
export function makeConsecutiveCache<T extends {}>(
  max: number,
  ttl: number
): LRUCache<string, T> {
  return new LRUCache<string, T>({ max, ttl });
}
