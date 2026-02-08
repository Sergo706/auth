import { NextFunction, Request, Response } from 'express';
import { getLogger } from '../utils/logger.js';
import { verifyMfaCode } from '../utils/verifyMfaCode.js';

/**
 * Verifies a custom MFA code submitted by the user.
 * 
 * @description
 * This controller is the final step in the custom MFA flow. 
 * It expects a JSON body containing the MFA code and relies on 
 * middleware (like `customMfaFlowsVerification`) to provide 
 * the necessary context via `req.link`.
 * 
 * Flow:
 * 1. Checks if the request is JSON.
 * 2. Delegates the actual verification and token rotation to `verifyMfaCode`.
 * 
 * @param {Request} req - Express request object.
 * Expected body: `{ code: string }`.
 * Expected `req.link`: Populated by `customMfaFlowsVerification` middleware.
 * @param {Response} res - Express response object.
 * @param {NextFunction} next - Express next function.
 * 
 * @returns {Promise<void>}
 * 
 * @example
 * // Verify a code
 * // POST /auth/verify-custom-mfa
 * // Body: { "code": "123456" }
 */
export async function verifyCustomMfa (req: Request, res: Response, next: NextFunction) {
  const log = getLogger().child({service: 'auth', branch: 'custom-mfa', visitorId: req.newVisitorId ?? req.link.visitor, reason: req.link.purpose})
  
  log.info(`Verifying custom mfa code...`)

 if (!req.is('application/json')) {
    log.warn('Content type is not json!')
    res.status(400).json({error: 'Bad Request.'})
    return; 
  }
  
 return verifyMfaCode(req, res, next, req.body.code, log);
}
