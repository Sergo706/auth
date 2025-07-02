import pinoNS from 'pino';
import { existsSync, mkdirSync } from 'fs';
import path from 'path';
import { config } from '../config/secret.js';
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

export const logger = (pinoNS as any)(
  {
    level: config.logs,
    timestamp: pinoNS.stdTimeFunctions.isoTime,
    mixin() { return { uptime: process.uptime() }; },
    redact: {
      paths: [
        'req.headers.authorization',
        'user.password',
        'accessToken',
        'refresh_token',
        '*.secret'
      ],
      censor: '[SECRET]'
    }
  },
  transport
);
