import { RateLimiterMemory, RateLimiterMySQL, RLWrapperBlackAndWhite } from 'rate-limiter-flexible';



/**
 * @description
 * Deletes a rate-limited key from both the underlying store and in-memory cache
 * for each provided limiter instance.
 *
 * @param {import('pino').Logger} log
 *   A Pino logger instance for recording reset operations.
 * @param {string} key
 *   The key to remove from the rate limiters (e.g., an IP or user identifier).
 * @param {Array<
 *   import('rate-limiter-flexible').RateLimiterMemory |
 *   import('rate-limiter-flexible').RateLimiterMySQL |
 *   RLWrapperBlackAndWhite
 * >} limiters
 *   An array of limiter instances whose state should be cleared for the given key.
 *
 * @returns {void}
 *
 * @see {@link ./jwtAuth/utils/limiters/utils/guard.js}
 *
 * @example
 * import pino from 'pino';
 * import { RateLimiterMemory, RateLimiterMySQL } from 'rate-limiter-flexible';
 * import { RLWrapperBlackAndWhite } from './RLWrapperBlackAndWhite';
 *
 * const logger = pino();
 * const memoryLimiter = new RateLimiterMemory({ points: 5, duration: 60 });
 * const mysqlLimiter = new RateLimiterMySQL({ points: 5, duration: 60, storeClient: db });
 * const wrapperLimiter = new RLWrapperBlackAndWhite(memoryLimiter, mysqlLimiter);
 *
 * // Remove "user:123" from all three limiters
 * resetLimiters(logger, 'user:123', [memoryLimiter, mysqlLimiter, wrapperLimiter]);
 */
export function resetLimiters(log: any, key: string, limiters: RateLimiterMemory[] | RateLimiterMySQL[] | RLWrapperBlackAndWhite[]) {
    limiters.forEach(async (limiter) => {
       await limiter.delete(key)
       log.info(`Deleted data from ${limiter.keyPrefix} limiter`);
    })
}
