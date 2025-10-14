import { Request, Response, NextFunction } from 'express';
import { isIP } from 'node:net';

/**
 * Ensure `req.ip` is a valid IP address. Responds 403 if invalid/missing.
 */
export const validateIp = (req: Request, res: Response, next: NextFunction) => {
  const ipAddress = req.ip;

  if (!ipAddress || isIP(ipAddress) === 0) {
    res.status(403).send('Forbidden');
    return
  }
  next();
};
