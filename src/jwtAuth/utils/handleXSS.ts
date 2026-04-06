import { banIp, updateIsBot, updateBannedIP } from '@riavzon/bot-detector';
import { Request } from "express";
import { getConfiguration } from '~~/config/configuration.js';
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
 * @returns {Promise<void>}
 *   Resolves when the XSS attempt has been logged and the visitor banned.
 * 
 * @see {@link ./handleXSS.js}
 *
 * @example
 * import pino from 'pino';
 * const logger = pino();
 *
 * const clean = await handleXSS(req, '<script>alert(1)</script>', logger);
 * 
 */
export async function handleXSS(req: Request, message: string, log: any) {
    log.warn(` XSS attempt banning visitor...`)
    const config = getConfiguration();
    // @ts-ignore
    await banIp(req.ip!, { score: config.botDetector.settings?.banScore ?? 100, reasons: ['XSS SCRIPTING ATTEMPT'] });
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