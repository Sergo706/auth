import { Request, Response, NextFunction, RequestHandler } from "express";


export function contentType(expected: string): RequestHandler {
    return(req: Request, res: Response, next: NextFunction) => {
        if (!req.is(expected)) {
            console.warn('unexpected content type')
            res.status(403).json({error: 'not allowed.'})
            return;
        };
        return next();
    };
  };