import { Response } from "express";
import { getLogger } from "../utils/logger.js";

export const reject = (reason: string, id:number | undefined, res:Response) => {
    const log = getLogger().child({service: 'HMAC', clientId: id})
    log.warn({Authorized: false, reason: reason})
    return res.status(401).send(reason);
}




