import { Request, Response, NextFunction } from 'express';
import { getLogger } from '../utils/logger.js';

/**
 * @summary Guard that accepts cookie-only requests for sensitive auth routes.
 * @description
 * Enforces a strict input contract for endpoints driven by refresh-token
 * cookies, preventing body/query/content-type based injection vectors.
 *
 * Rules:
 * - Requires cookie `session` (refresh token) → 401 if missing.
 * - Rejects any request body: parsed JSON, positive `content-length`, or
 *   `transfer-encoding: chunked` → 400.
 * - Rejects any query string → 400.
 * - Rejects any `Content-Type` header → 400.
 *
 * Status codes (unified JSON):
 * - 401: `{ error: 'Refresh token missing' }`
 * - 400: `{ error: 'Request body not allowed' | 'Query string not allowed' | 'Content-Type not allowed' }`
 *
 * Recommended order:
 * - `requireRefreshToken` → `cookieOnly` → your controller.
 * - Add `requireAccessToken` where both tokens are required (e.g. logout).
 *
 * @remarks Uses 400 for content-related rejections to standardize errors.
 *
 * @name cookieOnly
 * @function
 * @param req Express Request
 * @param res Express Response
 * @param next Express NextFunction
 * @example
 * // Rotate refresh+access tokens
 * app.post('/auth/user/refresh-session', requireRefreshToken, cookieOnly, rotateCredentials);
 * @example
 * // Logout requires both tokens
 * app.post('/auth/logout', requireRefreshToken, requireAccessToken, cookieOnly, handleLogout);
 * @see ../routes/TokenRotations.ts
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
