import { LRUCache } from "lru-cache";


export function makeConsecutiveCache<T extends {}>(
  max: number,
  ttl: number
): LRUCache<string, T> {
  return new LRUCache<string, T>({ max, ttl });
}
