import { sendLog } from "./telegramLogger.js";
import { banIp, updateIsBot, updateBannedIP } from "@riavzon/botdetector"
import { Request } from "express";
/**
 * @description
 * Punish a detected XSS attempt by banning the client at the firewall level and sending a Telegram alert.
 *
 * @param {import('express').Request} req
 *   The Express request object (used to identify the client/IP to ban).
 * @param {string} message
 *   The malicious XSS payload or message to log and process.
 * @param {import('pino').Logger} log
 *   A Pino logger instance for recording detection and ban events.
 *
 * @returns {Promise<string>}
 *   Resolves with the sanitized message string after handling the XSS attempt.
 *
 * @see {@link ./handleXSS.js}
 *
 * @example
 * import pino from 'pino';
 * const logger = pino();
 *
 * const clean = await handleXSS(req, '<script>alert(1)</script>', logger);
 * // `clean` now contains the sanitized version of the input
 */
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