import { sendLog } from "./telegramLogger.js";
import { banIp, updateIsBot, updateBannedIP } from "@riavzon/botdetector"
import { Request } from "express";

export async function handleXSS(req: Request, message: string, log: any) {
    log.warn(` XSS attempt banning visitor...`)
    await sendLog('XSS attempt', message);
    await banIp(req.ip!, { score: 10, reasons: ['XSS SCRIPTING ATTEMPT'] });
    await Promise.all([
     updateBannedIP(
    req.cookies.canary_id, 
    req.ip!, 
    'unknown',
    req.get('User-Agent') ?? 'unknown',
    { score: 10, reasons: ['XSS SCRIPTING ATTEMPT'] }),
     updateIsBot(true, req.cookies.canary_id)
    ])
     log.warn(`visitor banned.`)
     return; 
}