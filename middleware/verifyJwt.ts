import { verifyAccessToken } from "../accsessTokens.js";
import { Request, Response, NextFunction } from "express";

export const protectRoute = (req: Request, res: Response, next: NextFunction) => {
 const authHeader = req.headers['authorization'] || '';
 const token = authHeader.split(' ')[1]; 

   const result = verifyAccessToken(token);

   if (!result.valid || !result.payload) {
    res.status(401).json({ error: result.errorType});
    return;
  }

   const raw = result.payload;
  if (typeof raw.sub !== 'number' || typeof raw.visitor !== 'number') {
     res.status(401).json({ error: 'Malformed token payload' })
     return;
  }

    req.user = {
      userId: result.payload.sub,         
      visitor_id: result.payload.visitor,  
    };
 next();
}   
