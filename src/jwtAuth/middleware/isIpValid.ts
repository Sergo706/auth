import { Request, Response, NextFunction } from 'express';
import { isIP } from 'node:net';

export const validateIp = (req: Request, res: Response, next: NextFunction) => {
  const ipAddress = req.ip;

  if (!ipAddress || isIP(ipAddress) === 0) {
    res.status(403).send('Forbidden');
    return
  }
  next();
};