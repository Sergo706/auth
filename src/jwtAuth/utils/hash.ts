import * as argon2 from 'argon2'
import { getConfiguration } from '../config/configuration.js';
import { sendLog } from './telegramLogger.js';
import pino from 'pino';

/**
 * @description
 * Hash a plain-text password using Argon2 and log progress or errors.
 *
 * @param {string} password
 *   The plaintext password to hash.
 * @param {import('pino').Logger} log
 *   A Pino logger instance for recording the hashing process.
 *
 * @returns {Promise<string>}
 *   A promise resolving to the Argon2-hashed password string.
 *
 * @example
 * import pino from 'pino';
 * const logger = pino();
 *
 * const hashed = await hashPassword('mySecret123', logger);
 * // later...
 * const isValid = await verifyPassword('mySecret123', hashed);
 *
 * @see {@link ./hash.js}
 */
export async function hashPassword(passwords: string, log: pino.Logger) {
  const { password } = getConfiguration();
  log.info('Hashing password...')
  try {
    return await argon2.hash(passwords, {
      hashLength: password.hashLength ?? 50,
      timeCost: password.timeCost ?? 4, 
      memoryCost: password.memoryCost ?? 2 ** 18,                   
      secret: Buffer.from(password.pepper),
    })

  } catch (err) {
    log.fatal({err},'Password hashing failed')
    sendLog('Hash failed\n', `Failed to create a hashed password.\n Error: ${err}`)
  }
  log.info('Password hashed successfully')
}
/**
 * @description
 * Verify a plain-text password against an Argon2 hash.
 *
 * @param {string} hash
 *   The Argon2-hashed password to compare against.
 * @param {string} password
 *   The plain-text password provided by the user.
 *
 * @returns {Promise<boolean>}
 *   Resolves to `true` if the password matches the hash, otherwise `false`.
 *
 * @example
 * import pino from 'pino';
 * const logger = pino();
 *
 * const hashed = await hashPassword('mySecret123', logger);
 * const isValid = await verifyPassword(hashed, 'mySecret123');
 * if (isValid) {
 *   console.log('Password is correct');
 * } else {
 *   console.error('Invalid password');
 * }
 *
 * @see {@link ./hash.js}
 */
export async function verifyPassword(hash: string, passwords: string): Promise<boolean> {
   const { password } = getConfiguration();
  try {
    return await argon2.verify(hash, passwords, {
      secret: Buffer.from(password.pepper),
    })
  } catch {
    return false
  }
}

