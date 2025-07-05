import * as argon2 from 'argon2'
import { getConfiguration } from '../config/configuration.js';
import { sendLog } from './telegramLogger.js';
import pino from 'pino';

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

