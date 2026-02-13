import { NextFunction, Request, Response } from 'express';
import { getLogger } from '../utils/logger.js';
import { makeConsecutiveCache } from "../utils/limiters/utils/consecutiveCache.js"
import { verifyMfaCode } from '../utils/verifyMfaCode.js';

/**
 * @description
 * Verifies a one-time MFA code sent via email.  
 * - On success: sends `res.status(200).json({ accessToken, refreshToken })` and calls `next()`.  
 * - On failure:  
 *   - `400` Bad Request for malformed input.  
 *   - `401` Unauthorized for invalid or expired code.  
 *   - `403` Forbidden if the user is banned.  
 *   - `500` Internal Server Error on other errors.
 *
 * @name verifyMFA
 * @function
 * @param {import('express').Request} req
 *   The Express request object, containing the MFA code in `req.body`.
 * @param {import('express').Response} res
 *   The Express response object, used to send status codes and JSON.
 * @param {import('express').NextFunction} next
 *   The next middleware function.
 *
 * @returns {Promise<void>}
 *   Resolves after sending the appropriate HTTP response or calling `next()`.
 *
 * @see {@link ./middleware/verifyEmailMFA.js}
 *
 * @example
 * app.post('/mfa/verify', verifyMFA, (req, res) => {
 *   // on success, new tokens are in res.locals.tokens
 *   res.redirect('/dashboard');
 * });
 */
export async function verifyMFA (req: Request, res: Response, next: NextFunction) {
  const log = getLogger().child({service: 'auth', branch: 'mfa', visitorId: req.newVisitorId ?? req.link.visitor})
  
  log.info(`Verifying mfa code...`)

  if (req.link.purpose !== "MFA" || req.link.subject !== 'MAGIC_LINK_MFA_CHECKS') {
    log.warn('Invalid link purpose')
     res.status(400).json({ error: "Invalid link purpose" });
    return;
  }

 return verifyMfaCode(req, res, next, req.body.code, log);
}