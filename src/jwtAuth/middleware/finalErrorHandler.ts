import { Request,Response,NextFunction } from "express";
import { getLogger } from "../utils/logger.js";


/**
 * Last-resort Express error handler that normalizes error responses.
 *
 * Behavior:
 * - Logs the error with service context.
 * - Chooses status code from current `res.statusCode` if > 415, otherwise 500.
 * - Returns JSON payload `{ error: string }`.
 */
export const finalUnHandledErrors = ((err: any, req: Request, res: Response, next: NextFunction) => {
        const status = res.statusCode > 415 ? res.statusCode : 500;
        const log = getLogger().child({service: 'auth', branch: 'http'});
        log.error({ err })
        
        res.status(status).type('application/json').json({
            error: err.message || err || 'Internal Server Error'
     });
});