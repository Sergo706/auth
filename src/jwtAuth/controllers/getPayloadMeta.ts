import { RowDataPacket } from "mysql2";
import { getConfiguration } from "../config/configuration.js";
import { getLogger } from "../utils/logger.js";
import { Request, Response } from "express";

/**
 * Returns metadata about the authenticated access token for the current user.
 *
 * Mounted at `GET /secret/metadata` behind `requireAccessToken` →
 * `requireRefreshToken` → `protectRoute`.
 *
 * Validates user and visitor existence, then reports:
 * - Original JWT payload (as attached by `protectRoute`).
 * - Time until expiration and a rotation recommendation threshold (25% of TTL).
 * - Caller IP, user agent and current date for observability.
 *
 * Responses:
 * - 200: authorized with payload and TTL details.
 * - 401: not authenticated.
 * - 404: user/visitor not found.
 * - 500: internal validation error (logged).
 *
 * @param req Express Request with `user` context from `protectRoute`.
 * @param res Express Response
 */
    export async function getAccessTokenPayload (req: Request, res: Response) {
            const log = getLogger().child({service: 'auth', branch: "access token", type: 'getAccessTokenPayload'});
            const config = getConfiguration();
            const { userId, visitor_id, payload} = req.user!;
            const pool = config.store.main

        if (!req.user) {
            log.warn(`Unauthorized access attempt`);
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

      if (!row.length || !rowVisitor.length) {
         log.warn(`Unauthorized access attempt, user not found`)
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
    log.error(`Error validating user identity`)
    res.status(500).json({ authorized:false, reason:'Server error' })
    return;
  } 

  const TTL_MS = config.jwt.access_tokens.expiresInMs ?? 1000 * 60 * 15 
  const REFRESH_PERCENTAGE = 0.25;
  const REFRESH_THRESHOLD = TTL_MS * REFRESH_PERCENTAGE;
  const iatSec = payload.iat;
  const expSec = payload.exp;

  const iatMs = iatSec ? iatSec * 1000 : Date.now();
  const expMs = expSec ? expSec * 1000 : iatMs + TTL_MS;

  const msUntilExp = Math.max(0, expMs - Date.now());
  const shouldRotate = msUntilExp <= REFRESH_THRESHOLD;

  const roles = req.user.roles;
  log.info(`User has been authorized`)
  res.status(200).json({
    authorized: true,
    ipAddress: req.ip,
    userAgent:  req.get("User-Agent"),
    date: new Date().toISOString(),
    roles: roles ?? "No roles added with this token.",
    payload,
    msUntilExp,
    refreshThreshold: REFRESH_THRESHOLD,
    shouldRotate
  })
  return;
}
