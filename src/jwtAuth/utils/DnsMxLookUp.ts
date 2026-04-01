import dns from 'node:dns/promises';
import { domainToASCII }  from 'node:url';
import pino from 'pino';
import { makeConsecutiveCache } from './limiters/utils/consecutiveCache.js';

const cache = makeConsecutiveCache<{valid: boolean}>(300, 1000 * 60 * 60 * 24);

/**
 * @description
 * Checks if a domain has valid MX records.
 *
 * @param {string} addr - The domain name to validate (e.g., `'example.com'`).
 * @param {import('pino').Logger} log - A Pino logger instance for recording lookup steps or errors.
 *
 * @returns {Promise<boolean>}
 *   Resolves to `true` if the domain has at least one valid MX record, otherwise `false`.
 *
 * @see {@link ./DnsMxLookUp.js}
 *
 * @example
 * import pino from 'pino';
 * const logger = pino();
 *
 * const ok = await isValidDomain('example.com', logger);
 * if (ok) {
 *   console.log('Domain is valid for email delivery.');
 * } else {
 *   console.error('No valid MX records found.');
 * }
 */
export async function isValidDomain(addr: string, log: pino.Logger): Promise<boolean> {
const [local, domain] = addr.split('@');
 log.info(`Checking provided user email... domain: ${domain}`);

if (!local || !domain) {
    log.warn(`invalid addr: ${addr}@${domain}`);
    return false;
}

 const ascii = domainToASCII(domain.trim().toLowerCase());
 if (!ascii) {
    log.warn(`invalid domain: ${domain}`);
    return false
};

 const isCached = cache.get(ascii);
  if (isCached) {
    return isCached.valid;
  } 

 try {
    const mx = (await dns.resolveMx(ascii)).filter(r => r.exchange)
     if (mx.length > 0) {
        cache.set(ascii, {valid: true})
        log.info({mx},`Found a valid MX record`);
        return true;
     }
 } catch (err: any) {
    if (err.code !== 'ENODATA' && err.code !== 'ENOTFOUND') {
      log.fatal({ err }, 'Transient DNS failure - allowing user email');
      return true;           
    }
    log.info('No MX record found');
  }
  
log.info('Checking fallback A/AAAA…');
 const [a4, a6] = await Promise.allSettled([
    dns.resolve4(ascii),
    dns.resolve6(ascii)
 ]);
 const ARecordExists = a4.status === 'fulfilled' && a4.value.length > 0;
 const AAAARecordExists = a6.status === 'fulfilled' && a6.value.length > 0;
 log.info({ARecordExists, AAAARecordExists},'Check returned');

 cache.set(ascii, {valid: ARecordExists || AAAARecordExists})
 return ARecordExists || AAAARecordExists;
}