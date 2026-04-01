import pino from 'pino';
import { getDisposableEmailList } from '../config/configuration.js';

/**
 * @description
 * Detects whether a given email address belongs to a disposable‐email provider.
 *
 * @param {string} addr
 *   The email address to check.
 * @param {import('pino').Logger} log
 *   A Pino logger instance for recording detection steps or errors.
 *
 * @returns {Promise<boolean>}
 *   Resolves to `true` if the domain is disposable, otherwise `false`.
 *
 * @see {@link ./isEmailDisposable.js}
 *
 * @example
 * import pino from 'pino';
 * const logger = pino();
 *
 * if (await isDisposable('user@mailinator.com', logger)) {
 *   throw new Error('Disposable emails not allowed');
 * }
 */
export async function isDisposable(addr: string, log: pino.Logger): Promise<boolean> {

  log.info(`Checking if email is disposable...`)

  const domain = addr.split('@')[1]?.toLowerCase() ?? '';
  if (!domain) {
    log.warn('Invalid email supplied');
    return false;
  }

  log.info('Reading disposable list...');

  const exists = getDisposableEmailList().get(domain);
  const isBlocked = Boolean(exists?.domain);

  log.info(
    { domain, isBlocked },
    `Domain ${isBlocked ? 'is' : 'is NOT'} disposable`
  );

  return isBlocked;
}
