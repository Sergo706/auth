import { Request, Response, NextFunction } from "express";
import { logger } from "../utils/logger.js";
declare module 'express-serve-static-core' {
  interface Request {
    token?: string;
  }
}

export const requireAccessToken = (req: Request, res: Response, next: NextFunction) => {
        const log = logger.child({service: 'auth', branch: 'guard'})
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
