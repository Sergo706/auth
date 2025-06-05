import { Request, Response, NextFunction } from 'express';

export function cookieOnly(req: Request, res: Response, next: NextFunction) {
  if (typeof req.cookies.session !== 'string') {
     res.status(401).json({ error: 'Refresh token missing' });
    return
  }

  if (req.headers['content-length'] && Number(req.headers['content-length']) > 0) {
    res.status(413).json({ error: 'Request body not allowed' });
    return 
  }

  if (Object.keys(req.query).length !== 0) {
     res.status(400).json({ error: 'Query string not allowed' });
    return
  }

  if (req.headers['content-type']) {
     res.status(415).json({ error: 'Content-Type not allowed' });
    return
  }

  if (!req.headers.authorization?.startsWith('Bearer ')) {
     res.status(401).json({ error: 'Authorization header missing' });
    return
  }

 if (req.headers['transfer-encoding']) {
     res.status(413).json({ error: 'Request body not allowed' });
        return 
        }
  next();
}
