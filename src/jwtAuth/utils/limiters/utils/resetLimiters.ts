import { RateLimiterMemory, RateLimiterMySQL, RLWrapperBlackAndWhite } from 'rate-limiter-flexible';

export function resetLimiters(log: any, key: string, limiters: RateLimiterMemory[] | RateLimiterMySQL[] | RLWrapperBlackAndWhite[]) {
    limiters.forEach(async (limiter) => {
       await limiter.delete(key)
       log.info(`Deleted data from ${limiter.keyPrefix} limiter`);
    })
}
