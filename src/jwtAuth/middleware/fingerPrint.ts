import { getGeoData } from "@riavzon/botdetector";
import { parseUA } from "@riavzon/botdetector";
import type { FingerPrint } from '../types/fingerprint.js'
import { Request, Response, NextFunction } from "express";
import { getLogger } from "../utils/logger.js";

declare global {
    namespace Express {
         interface Request {
            fingerPrint: FingerPrint
        }
    }
}
/**
 * @description
 * Get fingerprints from the incoming request.
 * 
 * Accessible via req.fingerPrint
 * @param {Request} req
 * @param {Response} res
 * @param {NextFunction} next
 */
export async function getFingerPrint(req: Request, res: Response, next: NextFunction) {
 const log = getLogger().child({service: 'auth', branch: 'utils', type: 'fingerPrint'})
 try {
    const ipAddress = req.ip!;
    const userAgent = await parseUA(req.get('User-Agent'))
    const geoInfo = await getGeoData(req.ip);
    
    req.fingerPrint = /** @type {FingerPrint} */ {
      userAgent: req.get('User-Agent'),
      ip_address: ipAddress,
      ...geoInfo,
      ...userAgent
    }

 }  catch (err) {   
    log.error({err}, `Error getting visitor fingerprints`);
    console.error(err)
    return next();
 }  
 next();
}