import { Response } from "express";
import { getLogger } from "../utils/logger.js";

/**
 * Send a 401 Unauthorized response for failed HMAC validation and log the reason.
 *
 * @param reason Human-readable reason for rejection.
 * @param id Optional client identifier for logging context.
 * @param res Express response (used to send the 401).
 */
export const reject = (reason: string, id:number | undefined, res:Response) => {
    const log = getLogger().child({service: 'HMAC', clientId: id})
    log.warn({Authorized: false, reason: reason})
    return res.status(401).send(reason);
}



