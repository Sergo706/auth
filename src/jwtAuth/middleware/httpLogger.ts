import pinoNS from 'pino';
import pinoHttpNS from 'pino-http';
import  { stdSerializers, type Options as HttpOptions } from 'pino-http';
import { existsSync, mkdirSync } from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';
import type { Request, Response } from 'express';
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
        destination: `${LOG_DIR}/http.log`,
        mkdir:       true
      },
    },
  ]

})

export const httpLog = (pinoNS as any)(
  {
    level: 'info',
    timestamp: pinoNS.stdTimeFunctions.isoTime,
    mixin() { return { uptime: process.uptime() }; },
    redact: {
    paths: ['req.headers.authorization', 'req.cookies.session'],
    censor: '[SECRET]'
  }
  },
 
 transport
);

const httpOpts: HttpOptions<Request, Response> = {    
  logger: httpLog,

    genReqId: function (req: Request, res: Response) {
    const existingID = req.id ?? req.headers["x-request-id"]
    if (existingID) return existingID
    const id = randomUUID()
    res.setHeader('X-Request-Id', id)
    return id
  },

  serializers: {
    req: stdSerializers.req,
    res: stdSerializers.res,
    err: stdSerializers.err
  },
  autoLogging: {
    ignore: (req) => {
      const isPageView = req.originalUrl.match(/\.(css|js|png|jpe?g|svg|ico|woff2?|ttf|map|webp|json)$/i);
      const devTools = req.url.startsWith('/.well-known/');
      if (isPageView || devTools) return true;
      return false;
    }  
 
  },
  customProps: (req: Request, res: Response) => ({
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    FullUrl:  `${req.get(`x-forwarded-host`) ?? req.host}${req.originalUrl}`,
    cookies: req.cookies,
  }),

  customLogLevel: (req: Request, res: Response, err) => {
    if (err || res.statusCode >= 500) return 'error';
    if (res.statusCode >= 400) return 'warn';
    if (res.statusCode >= 300 && res.statusCode < 400) return 'info';
    if(req.url.startsWith('/.well-known/')) return 'silent';
    return 'info';
  },

   customSuccessMessage: (req: Request, res: Response, responseTime) => {
    if (res.statusCode === 404) {
    return `error:   404 page hit. \n referer: ${req.headers['referer']}\n
        latency: ${responseTime}
      `
    }
    return `${req.method} ${req.get(`x-forwarded-host`) ?? req.host}${req.originalUrl} completed `
  },

  customErrorMessage: (req: Request, res: Response, err) => {
    return `error: ${res.statusCode} on ${req.method} ${req.originalUrl}
      url: ${req.method} ${req.get('x-forwarded-host') ?? req.host}${req.originalUrl}
      Error name: ${err.name} \n
      Error message: ${err.message} \n
      Error stack: ${err.stack} \n
      `
  },

  customAttributeKeys: {
    req:    'httpRequest',     
    res:    'httpResponse',
    err:    'httpError',
    responseTime: 'latency',
    reqId:  'requestId'   
  },
}
export const httpLogger = (pinoHttpNS as any)(httpOpts);