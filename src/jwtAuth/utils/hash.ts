import * as argon2 from 'argon2'
import { config } from '../config/secret.js';
import { sendLog } from './telegramLogger.js';
import pino from 'pino';

export async function hashPassword(password: string, log: pino.Logger) {
  log.info('Hashing password...')
  try {
    return await argon2.hash(password, {
      hashLength: 50,
      timeCost: 4, 
      memoryCost: 2 ** 18,                   
      secret: Buffer.from(config.auth.userAuth.pepper!),
    })

  } catch (err) {
    log.fatal({err},'Password hashing failed')
    sendLog('Hash failed\n', `Failed to create a hashed password.\n Error: ${err}`)
  }
  log.info('Password hashed succesfuly')
}

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, password, {
      secret: Buffer.from(config.auth.userAuth.pepper!),
    })
  } catch {
    return false
  }
}

