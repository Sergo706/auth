import { Request, Response, NextFunction } from "express";

/**
 * Set standard no-cache response headers for sensitive auth endpoints.
 */
export const headers = (req: Request, res: Response, next :NextFunction) => {
    res.set({
        "Cache-Control": "no-cache, private, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
      })
      next();
    }
