import { Request, Response, NextFunction } from 'express';
import { getLogger } from '../utils/logger.js';

/**
 * @description
 * Enforces that a request can only post cookies to your server,
 * and requires you to set a Authorization Bearer header.
 * On failure, response:
 * 
 * res.status(401).json({ error: 'Refresh token missing' });
 * 
 * res.status(400).json({ error: 'Request body not allowed' });
 * 
 * res.status(400).json({ error: 'Query string not allowed' });
 * 
 * res.status(400).json({ error: 'Content-Type not allowed' });
 * 
 * .
 *
 * @name acceptCookieOnly
 * @function
 * @param {import('express').Request}   req
 * @param {import('express').Response}  res
 * @param {import('express').NextFunction} next
 * @see {@link ./middleware/postGuard.js}
 * @example
 * // only requests carrying the above conditions will reach your handler
 * app.post('/submit-comment', acceptCookieOnly, (req, res) => { … });
 */
export function cookieOnly(req: Request, res: Response, next: NextFunction) {
  const log = getLogger().child({service: 'auth', branch: 'content guard'})

  if (typeof req.cookies.session !== 'string') {
    log.warn('Refresh token missing')
     res.status(401).json({ error: 'Refresh token missing' });
    return
  }

  const hasParsedBody = req.body != null && typeof req.body === 'object' && Object.keys(req.body).length > 0;
  const contentLength = Number(req.headers['content-length'] ?? 0);
  const hasContentLength = Number.isFinite(contentLength) && contentLength > 0;       

  const hasChunked = typeof req.headers['transfer-encoding'] === 'string' && 
  req.headers['transfer-encoding'].toLowerCase().includes('chunked');
      

    if (hasParsedBody || hasContentLength || hasChunked) {
      log.warn('Request body not allowed');
      return res.status(400).json({ error: 'Request body not allowed' }); 
    }
    

  if (Object.keys(req.query).length !== 0) {
    log.warn('Query string not allowed')
     res.status(400).json({ error: 'Query string not allowed' });
    return
  }

  if (req.headers['content-type']) {
     log.warn('Content-Type not allowed')
     res.status(400).json({ error: 'Content-Type not allowed' });
    return
  }
  next();
}
