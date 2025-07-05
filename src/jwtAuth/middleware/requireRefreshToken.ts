import { Request, Response, NextFunction } from "express";
import { getLogger } from "../utils/logger.js";

export const requireRefreshToken = (req: Request, res: Response, next: NextFunction) => {
       const rawRefreshToken = req.cookies.session;
        const log = getLogger().child({service: 'auth', branch: 'guard'})
        if (!rawRefreshToken) {
            log.warn('Refresh token missing')
            res.status(401).json({error: 'Refresh token missing'});
            return;
        }; 
  next();
}