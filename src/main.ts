import { Router } from 'express';
import authRoutes from './jwtAuth/routes/auth.js';
/**
 *  @description
 * Part of the default configuration.
 * Main authentication routes: signup, login, and OAuth.
 * 
 * @type {import('express').Router}
 * @see {@link ./routes/auth.js}
 * @example
 * // mounted under /signup, /login, and  /auth/OAth/:providerName
 * app.use(authenticationRoutes);
 */
export const authenticationRoutes: import('express').Router = authRoutes;


import tempLinks from './jwtAuth/routes/magicLinks.js';
/**
 * @description
 * Part of the default configuration.
 * Magic-link routes: MFA and password reset.
 *
 * @type {Router}
 * @see {@link ./jwtAuth/routes/magicLinks.js}
 * @example
 * // Mounted under:
 * // "/auth/verify-mfa/:visitor" — MFA link generated, signed, and thrown dynamically.
 * // "/auth/forgot-password" — initiates the password reset process.
 * // "/auth/reset-password/:visitor" — reset link generated, signed, and thrown dynamically after initiation.
 * app.use(magicLinks);
 */
export const magicLinks: Router = tempLinks;

import tokenRotationRoutesDefault from './jwtAuth/routes/TokenRotations.js';
/**
 * @description
 * Part of the default configuration.
 * Token-rotation routes: issue refresh tokens, rotate them, revoke on logout, and detect anomalies.
 *
 * @type {Router}
 * @see {@link ./jwtAuth/routes/TokenRotations.js}
 * @example
 * // Mounted under "/token":
 * // "/auth/refresh-access" — rotates an access token.
 * // "/auth/user/refresh-session" — validates, rotates, and issues a new refresh token (revoking the old one if configured).
 * // "/auth/logout" — logs the user out and invalidates their current refresh token.
 * // "/auth/refresh-session/rotate-every" — rotates both access and refresh tokens.
 * app.use('/token', tokenRotationRoutes);
 */
export const tokenRotationRoutes: Router = tokenRotationRoutesDefault;


import { protectRoute as protectRouteOriginal } from './jwtAuth/middleware/verifyJwt.js';
/**
 * @description
 * Part of the default configuration.
 * Protects a route by verifying the JWT in the Authorization header.
 * On failure, responds with HTTP 401 Unauthorized.
 *
 * @name protectRoute
 * @function
 * @param {import('express').Request}   req   Express request object.
 * @param {import('express').Response}  res   Express response object.
 * @param {import('express').NextFunction} next  Express next handler.
 * @returns 
 *   req.user
 * 
 *   .userId
 * 
 *  .visitor_id
 * 
 *  .accessTokenId  the access token jti can be used with makeRateLimiter() to blacklist / revoke early
 * @see {@link ./jwtAuth/middleware/verifyJwt.js}
 * @example
 * // Protect any "/secret/data" route:
 * router.get(
 *   '/secret/data',
 *   requireAccessToken,
 *   requireRefreshToken,
 *   protectRoute,
 *   async (req: Request, res: Response) => { /* handler…  }
 * 
 * );
 */
export const protectRoute = protectRouteOriginal;
export { configuration } from './jwtAuth/config/configuration.js'
export { cookieOnly as acceptCookieOnly } from "./jwtAuth/middleware/postGuard.js";
export { requireAccessToken } from "./jwtAuth/middleware/requireAccessToken.js";
export { requireRefreshToken } from "./jwtAuth/middleware/requireRefreshToken.js";
export { contentType as validateContentType } from "./jwtAuth/middleware/validateContentType.js";
export { verifyMFA } from "./jwtAuth/middleware/verifyEmailMFA.js";
export { verifyNewPassword } from "./jwtAuth/middleware/verifyPasswordReset.js";
export { handleXSS } from "./jwtAuth/utils/handleXSS.js";
export { hashPassword, verifyPassword } from "./jwtAuth/utils/hash.js";
export { makeCookie } from "./jwtAuth/utils/cookieGenerator.js";
export { isValidDomain } from "./jwtAuth/utils/DnsMxLookUp.js";
export { default as sanitizeInput } from "./jwtAuth/utils/htmlSanitizer.js";
export { validateSchema as validateZodSchema } from "./jwtAuth/utils/validateZodSchema.js";
export { makeSafeString as makeSanitizedZodString } from "./jwtAuth/utils/zodSafeStringMaker.js";
export { waitSomeTime as timeEnumeration } from "./jwtAuth/utils/timeEnum.js";
export { sendLog as sendTelegramMessage } from "./jwtAuth/utils/telegramLogger.js";
export { sendSystemEmail } from "./jwtAuth/utils/systemEmails.js";
export { isDisposable } from "./jwtAuth/utils/isEmailDisposable.js";
export { sendTempMfaLink } from "./jwtAuth/utils/emailMFA.js";
export { sendTempPasswordResetLink } from "./jwtAuth/utils/changePassword.js";
export { getProviders as configureOauthProviders }  from './jwtAuth/utils/newOauthProvider.js';
export { createOauthUser } from "./jwtAuth/models/createOauthUser.js";
export { createUser } from "./jwtAuth/models/createUser.js";
export { findUserByProvider as findUserByOauthProvider } from "./jwtAuth/models/findUserByProvider.js";
export { generateAccessToken, verifyAccessToken} from "./accsessTokens.js"
export { revokeRefreshToken,
         rotateRefreshToken,
         generateRefreshToken, 
         consumeAndVerifyRefreshToken, 
         verifyRefreshToken } from "./refreshTokens.js";   
export { strangeThings } from "./anomalies.js"
export { verifyTempJwtLink as verifyTempLink, tempJwtLink as signNewTempLink } from "./tempLinks.js"
export { makeConsecutiveCache } from './jwtAuth/utils/limiters/utils/consecutiveCache.js';
export { consumeOrReject } from './jwtAuth/utils/limiters/utils/consumeOrReject.js';
export { guard } from './jwtAuth/utils/limiters/utils/guard.js';
export { resetLimiters } from './jwtAuth/utils/limiters/utils/resetLimiters.js';
export { makeRateLimiter, unionLimiter } from './jwtAuth/utils/limiters/rateLimit.js';
export { getLogger } from './jwtAuth/utils/logger.js';
export { getGeoData, parseUA, settings , initBotDetector, loadUaPatterns, detectBots, ApiResponse, addBannedCountries, warmUp } from '@riavzon/botdetector'
export { makeEmailTemplate, deleteTemplate, listTemplates } from './jwtAuth/utils/emailTemplateMaker.js'
/**
 * The Zod schema‐validation library, v4.
 *
 * @see {@link https://github.com/colinhacks/zod}
 * @example
 * import { z } from 'jwtAuth';
 * const userSchema = z.object({
 *   email: z.string().email(),
 *   age:   z.number().int().positive(),
 * });
 * type User = z.infer<typeof userSchema>;
 */
export { z } from 'zod/v4';