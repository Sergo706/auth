import { Request, Response, NextFunction } from "express";
import { getLogger } from "../utils/logger.js";
declare module 'express-serve-static-core' {
  interface Request {
    token?: string;
  }
}
/**
 * @description
 * Verifies that the incoming request carries a access‐token, verifies it downstream.
 * (in Authorization header or cookie). 
 * 
 * Fails 401 on invalid/absent token.
 *
 * @name requireAccessToken
 * @function
 * @param {Request}   req
 * @param {Response}  res
 * @param {NextFunction} next
 * @see {@link ./middleware/requireAccessToken.js}
 * @example
 * app.get('/protected', requireAccessToken, (req, res) => { … });
 */
export const requireAccessToken = (req: Request, res: Response, next: NextFunction) => {
        const log = getLogger().child({service: 'auth', branch: 'guard'})
        const authHeader = (req.get('authorization') || '').trim();

         if (!authHeader.startsWith('Bearer ')) {                       
          log.warn('Authorization header missing or malformed');
          res.status(401).json({ ok: false, error: 'Missing Bearer token' });
          return 
      }
       const token = authHeader.slice(7).trim();
       console.log(token)
        if (!token) {
            log.warn('Access token missing')
            res.status(401).json({error: 'Access token missing'});
            return;
        };
        req.token = token; 
  next();
}
