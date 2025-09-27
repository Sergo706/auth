import { NextFunction, Request, Response } from "express";
import { getLogger } from "../utils/logger.js";
import { RowDataPacket } from "mysql2";
import { getConfiguration } from "../config/configuration.js";


/**
 * @summary Authorizes BFF access for the current session/user.
 * @description
 * Validates that `req.user` has been populated by upstream auth middleware
 * and that both the user and visitor exist in the data store. Responds with
 * a normalized JSON payload indicating whether the caller is authorized.
 *
 * Responses:
 * - 200: `{ authorized: true, ipAddress, userAgent, date }`
 * - 401: `{ authorized: false, reason: 'Not authenticated', ... }` when `req.user` is missing
 * - 404: `{ authorized: false, reason: 'Not found', ... }` when user/visitor not found
 * - 500: `{ error: 'Could not send MFA code, try again later' }` may occur upstream; internal errors are logged here
 *
 * Requirements:
 * - `protectRoute` must run before this handler to set `req.user`
 * - Refresh cookies are validated upstream; this handler trusts `req.user`
 *
 * @name allowBffAccess
 * @function
 * @param {Request} req Express request (expects `req.user`)
 * @param {Response} res Express response
 * @param {NextFunction} next Express next function
 * @returns {Promise<void>} Sends JSON and terminates the response.
 * @example
 * router.get('/secret/data', requireAccessToken, requireRefreshToken, protectRoute, allowBffAccess)
 * @see ../middleware/verifyJwt.js
 */
export const allowBffAccess = async (req: Request, res: Response, next: NextFunction) => {
  const log = getLogger();
  const config = getConfiguration();

  const { userId, visitor_id, } = req.user!;
  const pool = config.store.main

  const baseLog = log.child({
    ipAddress:  req.ip,
    reqId:      req.id,
    userAgent:  req.get("User-Agent"),
    endpoint:   req.originalUrl,
    canaryId:   req.cookies.canary_id,
  });
  
  if (!req.user) {
    baseLog.warn(`Unauthorized access attempt`);
    res.status(401).json({
        authorized: false,
        reason: 'Not authenticated',
        ipAddress: req.ip,
        userAgent:  req.get("User-Agent"),
        date: new Date().toISOString()
    })
    return;
 }

  try {
      const [row] = await pool.execute<RowDataPacket[]>('SELECT * FROM users WHERE id = ?', [userId])
      const [rowVisitor] = await pool.execute<RowDataPacket[]>('SELECT * FROM visitors WHERE visitor_id = ?', [visitor_id])

      if (!row || !rowVisitor) {
         baseLog.warn(`Unauthorized access attempt, user not found`)
         res.status(404).json({
            authorized: false,
            reason: 'Not found',
            ipAddress: req.ip,
            userAgent:  req.get("User-Agent"),
            date: new Date().toISOString()
        })
         return;
      } 

  } catch(error) {
    baseLog.error(`Error validating user identity`)
    return;
  } 

  baseLog.info(`User has been authorized`)
  res.status(200).json({
    authorized: true,
    ipAddress: req.ip,
    userAgent:  req.get("User-Agent"),
    date: new Date().toISOString()
  })
  return;
}
