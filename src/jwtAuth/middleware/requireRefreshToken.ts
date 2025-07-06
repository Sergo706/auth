import { Request, Response, NextFunction } from "express";
import { getLogger } from "../utils/logger.js";


/**
 * @description
 * Verifies that the incoming request carries a refresh‐token.
 * Used for token‐rotation, verification or logout endpoints on downstream.
 *
 * @name requireRefreshToken
 * @function
 * @param {Request}   req
 * @param {Response}  res
 * @param {NextFunction} next
 * @see {@link ./middleware/requireRefreshToken.js}
 * @example
 * app.post('/token/rotate', requireRefreshToken, (req, res) => { … });
 */
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