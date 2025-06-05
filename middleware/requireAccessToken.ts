import { Request, Response, NextFunction } from "express";

export const requireAccessToken = (req: Request, res: Response, next: NextFunction) => {
       const authHeader = req.headers['authorization'] || '';
       const token = authHeader.split(' ')[1]; 
        if (!token) {
            res.status(401).json({error: 'Access token missing'});
            return;
        }; 
  next();
}