import pinoNS from 'pino';
import { existsSync, mkdirSync } from 'fs';
import path from 'path';
import { getConfiguration } from '../config/configuration.js';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const LOG_DIR = path.resolve(__dirname, '..', '..', '..', 'logs');
if (!existsSync(LOG_DIR)) mkdirSync(LOG_DIR, { recursive: true });

const transport = pinoNS.transport({
  targets: [
    {
      target: 'pino/file',
      level:  'info',
      options: {
        destination: `${LOG_DIR}/info.log`,
        mkdir:       true
      }
    },
    {
      target: 'pino/file',
      level:  'warn',
      options: {
        destination: `${LOG_DIR}/warn.log`,
        mkdir:       true
      }
    },
    {
      target: 'pino/file',
      level:  'error',
      options: {
        destination: `${LOG_DIR}/errors.log`,
        mkdir:       true
      }
    }
  ]
});
let logger: pinoNS.Logger;  

/**
 * @description
 * Get the logger of the library and log custom events you need.  
 * 3 files will be created under node_modules/@riavzon/jwtauth, in a structured json lines.
 * 
 * info.log contains info waring, error, and fatal level logs.
 * 
 * warn contains waring, error, and fatal level logs
 * 
 * error.log contains error, and fatal level logs
 *
 *
 * @returns {logger}
 * Configured pino.Logger
 *
 * @example
 * const log = getLogger().child({service: 'auth', branch: 'logout'});
 * log.info('loggin user out...')
 * @see {@link https://github.com/pinojs/pino}
 */
export function getLogger() {
  if (logger) return logger;       
  const { logLevel } = getConfiguration();
  logger = (pinoNS as any)(
    {
      level: logLevel,             
      timestamp: pinoNS.stdTimeFunctions.isoTime,
      mixin() { return { uptime: process.uptime() }; },
      redact: {
        paths: [
          'req.headers.authorization',
          'user.password',
          'accessToken',
          'refresh_token',
          'cookie',
          'cookies',
          'canary_id',
          'req.cookies',
          'req.cookie',
          'access_token',
          'email',
          'name',
          '*.secret'
        ],
        censor: '[SECRET]'
      }
    },
    transport
  );

  return logger;
}
