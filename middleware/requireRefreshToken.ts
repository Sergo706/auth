import { Request, Response, NextFunction } from "express";

export const requireRefreshToken = (req: Request, res: Response, next: NextFunction) => {
       const rawRefreshToken = req.cookies.session;

        if (!rawRefreshToken) {
            res.status(401).json({error: 'Refresh token missing'});
            return;
        }; 
  next();
}