// // @ts-check
// main routes and middlewares// The ones that make the lib usable, the "Default"
/**
 * @description
 * The JWT auth library’s configuration object.
 * Contains the core configuration to make the library usable.
 *  
 * @module jwtAuth/config
 * @see {@link ./jwtAuth/types/config.js}
 */
export { configuration } from './jwtAuth/config/configuration.js'

// @ts-check
/**
 * @module jwtAuth/routes
 *
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
export { default as authenticationRoutes } from './jwtAuth/routes/auth.js';
/** 
 * @description
 * Part of the default configuration.
 * Magic‐link routes: Mfa, and password reset.
 * 
 * @type {import('express').Router}
 * @see {@link ./routes/magicLinks.js}
 * @example
 * // mounted under 
 * "/auth/verify-mfa/:visitor" for mfa, generated, signed and throwed after dynamically use.
 * "/auth/forgot-password", for starting a password reset process.
 * "/auth/reset-password/:visitor" generated, signed and throwed dynamically, after password initiation succeeded, and after first use.
 * app.use(magicLinks);
 */
export { default as magicLinks } from './jwtAuth/routes/magicLinks.js';

/** 
 * @description
 * Part of the default configuration.
 * Token‐rotation routes: issue refresh tokens, rotate them, revoke on logout and detect anomalies.
 * 
 * @type {import('express').Router}
 * @see {@link ./routes/TokenRotations.js}
 * @example
 * // mounted under /token
 * '/auth/refresh-access', hit to rotated an access token.
 * '/auth/user/refresh-session' hit to validated, rotated, get new, if refresh_tokens.rotateOnEveryAccessExpiry is true on every access token rotation, the current refresh token is revoked and rotated.
 * '/auth/logout', hit to log the user out, and invalidate its token on the current device he in.
 * '/auth/refresh-session/rotate-every', hit to rotated both, access and refresh tokens. 
 * app.use('/token', tokenRotationRoutes);
 */
export { default as tokenRotationRoutes } from './jwtAuth/routes/TokenRotations.js';

/** 
 * @description
 * Part of the default configuration.
 * Protects a route by verifying the incoming JWT in Authorization header.
 * On failure, responds 401 Unauthorized.
 *
 * @name protectRoute
 * @function
 * @param {import('express').Request}   req
 * @param {import('express').Response}  res
 * @param {import('express').NextFunction} next
 * @see {@link ./middleware/verifyJwt.js}
 * @example
 * // Protect any /secret/data route with protectRoute and requireAccessToken, requireRefreshToken middlewares, and get req.user for a 
 *  specific user identifiers.
 * 
 * router.get('/secret/data',requireAccessToken, requireRefreshToken, protectRoute, async (req: Request, res: Response) => {
 * const { userId, visitor_id } = req.user;
 *
 * const [row] = await pool.execute<RowDataPacket[]>('SELECT * FROM users WHERE id = ?', [userId])
 * const [rowVisitor] = await pool.execute<RowDataPacket[]>('SELECT * FROM visitors WHERE visitor_id = ?', [visitor_id])
 *
 * if (!row || !rowVisitor) {
 *  res.status(404).end();
 *   return;
 * } 
 *
 * res.json({
 *  youAre: row[0],
 *  visitor_info:  rowVisitor[0],
 * });
*});
 */
export { protectRoute } from './jwtAuth/middleware/verifyJwt.js';


/**
 * @description
 * Enforces that a request can only post cookies to your server,
 * and requires you to set a Authorization Bearer header.
 * On failure, response:
 * res.status(401).json({ error: 'Refresh token missing' });
 * res.status(401).json({ error: 'Authorization header missing' });
 * res.status(413).json({ error: 'Request body not allowed' });
 * res.status(400).json({ error: 'Query string not allowed' });
 * res.status(415).json({ error: 'Content-Type not allowed' });
 * res.status(413).json({ error: 'Request body not allowed' });
 * .
 *
 * @name acceptCookieOnly
 * @function
 * @param {import('express').Request}   req
 * @param {import('express').Response}  res
 * @param {import('express').NextFunction} next
 * @see {@link ./middleware/postGuard.js}
 * @example
 * // only requests carrying the above conditions will reach your handler
 * app.post('/submit-comment', acceptCookieOnly, (req, res) => { … });
 */
export { cookieOnly as acceptCookieOnly } from "./jwtAuth/middleware/postGuard.js";

/**
 * @description
 * Verifies that the incoming request carries a access‐token, verifies it downstream.
 * (in Authorization header or cookie). Fails 401 on invalid/absent token.
 *
 * @name requireAccessToken
 * @function
 * @param {import('express').Request}   req
 * @param {import('express').Response}  res
 * @param {import('express').NextFunction} next
 * @see {@link ./middleware/requireAccessToken.js}
 * @example
 * app.get('/protected', requireAccessToken, (req, res) => { … });
 */
export { requireAccessToken } from "./jwtAuth/middleware/requireAccessToken.js";

/**
 * @description
 * Verifies that the incoming request carries a refresh‐token.
 * Used for token‐rotation, verification or logout endpoints on downstream.
 *
 * @name requireRefreshToken
 * @function
 * @param {import('express').Request}   req
 * @param {import('express').Response}  res
 * @param {import('express').NextFunction} next
 * @see {@link ./middleware/requireRefreshToken.js}
 * @example
 * app.post('/token/rotate', requireRefreshToken, (req, res) => { … });
 */
export { requireRefreshToken } from "./jwtAuth/middleware/requireRefreshToken.js";

/**
 * @description
 * Enforces that `Content-Type` header matches the expected type.
 * Fails 403 Unsupported Media Type otherwise.
 *
 * @name validateContentType
 * @function
 * @param {string} expectedType  e.g. 'application/json'
 * @returns {import('express').RequestHandler}
 * @see {@link ./middleware/validateContentType.js}
 * @example
 * // Only allow JSON bodies
 * app.post('/api/data', validateContentType('application/json'), handler);
 */
export { contentType as validateContentType } from "./jwtAuth/middleware/validateContentType.js";

/**
 * @description
 * Verifies a one-time MFA code sent via email. On success, response with new tokens 200,
 *  and continues; on failure, responds 400, 403 only if user got banned, 401 on Invalid or expired code, 500 on error.
 *
 * @name verifyMFA
 * @function
 * @param {import('express').Request}   req
 * @param {import('express').Response}  res
 * @param {import('express').NextFunction} next
 * @see {@link ./middleware/verifyEmailMFA.js}
 * @example
 * app.post('/mfa/verify', verifyMFA, (req, res) => { … });
 */
export { verifyMFA } from "./jwtAuth/middleware/verifyEmailMFA.js";

/**
 * @description
 * Verifies the “reset password” token (e.g. from email link), ensures
 * it’s valid and not expired. On success, returns res.status(200).json({ success: true }), to redirect to login page.
 *
 * @name verifyNewPassword
 * @function
 * @param {import('express').Request}   req
 * @param {import('express').Response}  res
 * @param {import('express').NextFunction} next
 * @see {@link ./middleware/verifyPasswordReset.js}
 * @example
 * app.post('/password/reset', verifyNewPassword, (req, res) => { … });
 */
export { verifyNewPassword } from "./jwtAuth/middleware/verifyPasswordReset.js";


// src/jwtAuth/utils/index.js
// @ts-check
/**
 * @module jwtAuth/utils
 */
/**
 * @description
 * punish already detected XSS attempt
 * when called bans the user on ufw level, and send you a telegram message.
 * @see {@link ./handleXSS.js}
 * @params 
 * @example
 * 
 * const clean = handleXSS(req, message: string, log: pino.Logger);
 */
export { handleXSS } from "./jwtAuth/utils/handleXSS.js";
/**
 * @description
 * Hash and verify passwords using argon2.
 * @see {@link ./hash.js}
 * @example
 * const hash = await hashPassword(password: string, log: pino.Logger);
 * const verify   = await verifyPassword(password: string,, hash);
 */
export { hashPassword, verifyPassword } from "./jwtAuth/utils/hash.js";

/**
 * @description
 * Generates a cookie string (name=value; options…) for setting in responses.
 * if name startsWith("__Host-") defaults are:     
 *  options.secure = true;
*  options.path = "/";
*  delete options.domain;
*   
* if name.startsWith("__Secure-") defaults are: options.secure = true;
 * @param {string} name
 * @param {string} value
 * @param {import('express').CookieOptions} [opts]
 * @returns {string}
 * @see {@link ./cookieGenerator.js}
 * @example
 *   makeCookie(res, name: string, value: string, {
      httpOnly: true,
      sameSite: "strict", 
      expires: 1234,
      secure: true,
      domain: example.com,
      path: '/'
   })
 */
export { makeCookie } from "./jwtAuth/utils/cookieGenerator.js";

/**
 * @description
 * Checks if a domain has valid MX records.
 * @param {string} domain
 * @returns {Promise<boolean>}
 * @see {@link ./DnsMxLookUp.js}
 * @example
 * const ok = await isValidDomain('email@example.com', log: pino.Logger);
 */
export { isValidDomain } from "./jwtAuth/utils/DnsMxLookUp.js";

/**
 * @description
 * Decode uris characters unicode, NFKC and sanitizes arbitrary HTML.
 * @param {string} inputHtml
 * @returns {string}
 * @see {@link ./htmlSanitizer.js}
 * @example
 * const safe = sanitizeInput(userSubmittedHtml);
 * @returns 

 * { vall: stripped, 
      results: {
        htmlFound: boolean,
        tags: {
         tagName: string,  
       }
    } 
    }
 */
export { default as sanitizeInput } from "./jwtAuth/utils/htmlSanitizer.js";

/**
 * @description
 * Validates a zod provided schema, and raw data against it.
 * @param {import('zod').ZodTypeAny} schema
 * @returns {import('express').RequestHandler}
 * @see {@link ./validateZodSchema.js}
 * @example 
 * validateZodSchema(passwords, req.body, req, log)
 *  @returns validated zod schema object or { valid: boolean; errors: object | string; }
 * 
 */
export { validateSchema as validateZodSchema } from "./jwtAuth/utils/validateZodSchema.js";

/**
 * @description
 * Make a safe Zod string that will be sanitized.
 * @params 
 * min: number,
 * max: number
 * pattern?: RegExp
 * patternMsg?: string
 * @returns {string}
 * @see {@link ./zodSafeStringMaker.js}
 * @example
 * export const email = z.strictObject({ 
     email:makeSanitizedZodString({
         min: 10,
         max: 80,
         pattern: /^(?!\.)(?!.*\.\.)[A-Za-z0-9_'-.]+[A-Za-z0-9_-]@[A-Za-z][A-Za-z-]*(?:\.[A-Za-z]{1,4}){1,3}$/,
         patternMsg: `Please Enter a valid email`
     })
 }).required();
 */
export { makeSafeString as makeSanitizedZodString } from "./jwtAuth/utils/zodSafeStringMaker.js";
/**
 * @description
 * Pauses execution for a given number of milliseconds.
 * @param {number, pino.Logger} ms
 * @returns {Promise<void>}
 * @see {@link ./timeEnum.js}
 * @example
 * await timeEnumeration(1000); // wait 1 second
 */
export { waitSomeTime as timeEnumeration } from "./jwtAuth/utils/timeEnum.js";

/**
 * @description
 * Logs a message to your configured Telegram chat.
 * @param {string} title
 * @param {string} message
 * @returns {Promise<void>}
 * @see {@link ./telegramLogger.js}
 * @example
 * await sendTelegramMessage('User signed up', `a new User is Just signed up! `);
 */
export { sendLog as sendTelegramMessage } from "./jwtAuth/utils/telegramLogger.js";


/**
 * @description
 * Sends emails via your SMTP provider.
 * @param {recipients: string[] | string, userData: EmailData, template: string} mailOptions
 * @returns {Promise<void>}
 * @see {@link ./systemEmails.js}
 * @example
 * await sendSystemEmail(email@example.com, email, msg, welcomeTemplate);
 */
export { sendSystemEmail } from "./jwtAuth/utils/systemEmails.js";

/**
 * @description
 * Detects disposable‐email domains.
 * @param {string, pino.Logger} email
 * @returns {boolean}
 * @see {@link ./isEmailDisposable.js}
 * @example
 * if (isDisposable(userEmail)) throw new Error('Disposable emails not allowed');
 */
export { isDisposable } from "./jwtAuth/utils/isEmailDisposable.js";

/**
 * @description
 * Sends a one-time MFA link via email to a valid registered user.
 *
 * @param {user: { userId: number; visitor: number }, sessionToken: string, } opts
 * @returns {Promise<void>}
 * @see {@link ./emailMFA.js}
 * @example
 * await sendTempMfaLink(user: { userId: 13; visitor: 14 }, refreshToken);
 */
export { sendTempMfaLink } from "./jwtAuth/utils/emailMFA.js";

/**
 * @description
 * Sends a password‐reset link via email to a valid registered user.
 * @param {string} opts
 * @returns {Promise<void>}
 * @see {@link ./changePassword.js}
 * @example
 * await sendTempPasswordResetLink('email@example.com');
 */
export { sendTempPasswordResetLink } from "./jwtAuth/utils/changePassword.js";

/**
 * @description
 * Retrieves and instantiates all OAuth providers defined in your application configuration,
 * and optionally registers additional provider(s) passed as an argument.
 * If `newProviders` is provided, those configs are registered first.
 *
 * @function configureOauthProviders
 * @param {import('../models/provider').ProviderConfig|import('../models/provider').ProviderConfig[]} [newProviders]
 *   A single provider config or an array of provider configs to register
 *   before returning the full list.
 * @returns {import('../models/provider').OAuthProvider[]}
 *   An array of instantiated OAuthProvider objects, including any newly registered ones.
 * @see {@link ./newOauthProvider.js}
 * @example
 * // 1 Use only configured providers:
 * const providers = configureOauthProviders();
 *
 * // 2 Register one extra provider on the fly:
 * import { customConfig } from './myCustomProvider';
 * const providersWithCustom = configureOauthProviders(customConfig);
 *
 * // 3 Register multiple extras:
 * import { googleConfig, facebookConfig } from './oauthConfigs';
 * const allProviders = configureOauthProviders([googleConfig, facebookConfig]);
 */
export { getProviders as configureOauthProviders }  from './jwtAuth/utils/newOauthProvider.js';

/**
 * @description
 * Create a new OAuth user record.
 * @param {cookie: string}
 * @param { import('./jwtAuth/types/newUser.js').StandardProfile}
 * @param {provider: string}
 * @returns {Promise<import('./models/user').User>}
 * @see {@link ./models/createOauthUser.js}
 * @example
 * const user = await createOauthUser(
 *   req.cookie.canary_id,
 *   StandardProfile,
 *   '1234567890',
 * );
 * @returns
 * { success: boolean;  accessToken?: string; refreshToken?: IssuedRefreshToken; duplicate?: true;  }
 */
export { createOauthUser } from "./jwtAuth/models/createOauthUser.js";

/**
 * @description
 * Create a new local user.
 * @param {cookie: string} str
 * @param {import ('./jwtAuth/types/newUser.js').NewUser} str
 * @returns {Promise<import('./models/user').User>}
 * @see {@link ./models/createUser.js}
 * @example
 * const user = await createUser(
 *   req.cookie.canary_id,
 *   data
 * );
 * @returns { success: boolean;  accessToken?: string; refreshToken?: IssuedRefreshToken; duplicate?: true;  }
 */
export { createUser } from "./jwtAuth/models/createUser.js";

/**
 * @description
 * Find a user by their OAuth provider details.
 * @param {{ provider: string; providerId: string }} opts
 * @returns {Promise<import('./models/user').User|null>}
 * @see {@link ./models/findUserByProvider.js}
 * @example
 * const user = await findUserByOauthProvider(
 *   provider: 'github',
 *   subId: '987654321'
 * );
 * @returns { user: boolean; accessToken?: string; refreshToken?: IssuedRefreshToken; }
 */
export { findUserByProvider as findUserByOauthProvider } from "./jwtAuth/models/findUserByProvider.js";

/**
 * @description
 * Generate a short-lived access token.
 * @function generateAccessToken @param { user: {id: number, visitor_id: number, jti: string} }
 * @returns {string}
 * @example
 * const token = generateAccessToken(user: {id: 1, visitor_id: 12, jti: uuid});
 * 
 * @function verifyAccessToken @param {token: string, Payload: import('./accsessTokens.js').claims} }
 * @returns {{valid: boolean, payload?: JwtPayload, errorType?: string}}
 * @example
 * const payload = verifyAccessToken(token: string, Payload: claims);
 * 
 * @see {@link ./accsessTokens.js}
 */
export { generateAccessToken, verifyAccessToken} from "./accsessTokens.js"

/**
 * @description
 * generate and hash a fresh refresh token.
 * @function generateRefreshToken @param { ttl: number, userId: number }
 * @returns {import('./refreshTokens.js').IssuedRefreshToken}
 * @example
 *  generateRefreshToken(1000 * 60 * 60 * 24 * 3, 14);
 * @description
 * search and rotate provided refresh token if the token is hashed set hashed param as true.
 * @function rotateRefreshToken @param {ttl: number, userId: number, oldClientToken: string, hashed?: boolean}
 * @returns { rotated: boolean, raw?: string, hashedToken?: string, expiresAt?: Date }
 * @example rotateRefreshToken(1000 * 60 * 60 * 24 * 3, 14, oldToken, true);
 * @description
 * revoke any valid client token. if the token is hashed set hashed param as true.
 * @function revokeRefreshToken @param {clientToken: string, hashed?: boolean}
 * @returns { success: boolean }
 * @example revokeRefreshToken('clientToken', true);
 * @description
 * verify a refresh token revoke on expiry and detect is a revoked token being used again if so, the token deleted.
 * if the token is hashed set hashed param as true.
 * @function verifyRefreshToken @param {clientToken: string, hashed?: boolean} 
 * @returns { valid: boolean; userId?: number; visitor_id?: number;  reason?: string, sessionTTL?:Date }
 * @example
 * verifyRefreshToken('clientToken', true);
 * @description
 * verify and consume a refresh token after calling this method on a token, a token cant be used a second time, suitable when refresh tokens 
 *  rotates on every access token rotation.
 *  Additionally, detect if a revoked or used token being used again if so, the token is deleted, and the user is forced to log in again on all
 *  opened sessions.
 * if the token is hashed set hashed param as true.
 * @function consumeAndVerifyRefreshToken @param {clientToken: string, hashed?: boolean} 
 * @returns { valid: boolean; userId?: number; visitor_id?: number;  reason?: string, sessionTTL?:Date }
 * @example
 * consumeAndVerifyRefreshToken('clientToken', true);
 * @see {@link ./refreshTokens.js}
*/
export { revokeRefreshToken,
         rotateRefreshToken,
         generateRefreshToken, 
         consumeAndVerifyRefreshToken, 
         verifyRefreshToken } from "./refreshTokens.js";

/**
 * @description
 * Anomaly-detection utilities bot-detection heuristics, ip differences, device differences etc.
 * @returns {{valid: boolean;reason: string;reqMFA: boolean;userId?: number;visitorId?: number;}}
 * @param {token: string, cookie: string, ipAddress: string, ua: string, rotated: boolean} 
 * @see {@link ./anomalies.js}
 * @example
 * const {valid, reason, reqMFA, userId, visitorId} =  strangeThings(rawRefreshToken, canary_id, req.ip!, req.get('User-Agent')!, false);
 *     if (!valid && reqMFA) handleMFA
 *     if (!valid && !reqMFA) handleAnomaly
 *                 
 */         
export { strangeThings } from "./anomalies.js"

/**
 * @description
 * Create and verify short lived JWT links, password-reset, magic-link, mfa etc.
 *
 * @function verifyTempLink @param {token: string, purpose: string, subject: string, jti: string}
 * @returns {{valid: boolean, payload?: JwtPayload, errorType?: string}}
 * @example
 * const payload = verifyTempLink('secret', MFA, subject, uuid);
 * 
 * @function verifyTempLink @param {import('./tempLinks.js').LinkTokenPayload }
 * @returns {token: string}
 * @example 
 * const new = verifyTempLink(payload);
 * @see {@link ./tempLinks.js}
 */
export { verifyTempJwtLink as verifyTempLink, tempJwtLink as signNewTempLink } from "./tempLinks.js"

// rate limiters
/**
 * Creates a consecutive custom cache.
 *
 * @template T
 * @param {number} max   Maximum number of cache to store.
 * @param {number} ttl   Time in milliseconds to retain entries.
 * @returns {{
 *   get(key: string): T | undefined;
 *   set(key: string, value: T): void;
 *   reset(key: string): void;
 *   delete(key: string): void;
 * }}
 * @see {@link ./jwtAuth/utils/limiters/utils/consecutiveCache.js}
 * @example
 * const loginCache = makeConsecutiveCache<{ count: number }>(5, 60_000);
 * loginCache.set('user:123', { count: 1 });
 */
export { makeConsecutiveCache } from './jwtAuth/utils/limiters/utils/consecutiveCache.js';

/**
 * @description
 * Attempts to consume a key for the given limiter or 
 * response with res.set('Retry-After', String(retrySec)).status(429).json({
 *       error: 'Too many requests',
 *       retry: retrySec,
 *     }); 
 *   if the limit is exceeded.
 *
 * @param { limiter: any,key: string,res: Response,log: any}
 * @returns {RateLimiterRes}  `RateLimiterRes` if consumption succeeded.
 * @returns {null}  When the limit has been reached.
 * @see {@link ./jwtAuth/utils/limiters/utils/consumeOrReject.js}
 * @example
 * 
 *   const rlRes: RateLimiterRes | null = await consumeOrReject(limiter, key, res, log);
 *   if (rlRes === null) { do something }
 */
export { consumeOrReject } from './jwtAuth/utils/limiters/utils/consumeOrReject.js';

/**
 *  @description
 * a method to guard endpoints using your configured limiter.
 *  if a cache exceeded an of how many time a key can get rate limited, key is blacklisted.
 * @param {  limiter: Limiter, key: string,cache: LRUCache<string, CacheEntry>,maxBans: number,label: string,log: pino.Logger,res: Response,seconds?: number}
 * @returns {false} for a banned or rate limited key, true request may proceed.
 * @see {@link ./jwtAuth/utils/limiters/utils/guard.js}
 * @example
 * // In a handlers:
 *   if (!(await guard(Limiter, key, cache, 1, 'label', pino.Logger, res))) return;
 */
export { guard } from './jwtAuth/utils/limiters/utils/guard.js';

/**
 *  @description
 *  a method to delete rate limited keys from store and memory.
 * 
 * @param {log: pino.Logger, key: string, limiters: RateLimiterMemory[] | RateLimiterMySQL[] | RLWrapperBlackAndWhite[]}
 * @see {@link ./jwtAuth/utils/limiters/utils/guard.js}
 * @example
 * 
 *   resetLimiters(pino.Logger, key, [limiter1, limiter2, ...]);
 */
export { resetLimiters } from './jwtAuth/utils/limiters/utils/resetLimiters.js';

/**
 *  @description
 *  Create a new configurable limiter.
 * 
 * 
 * @function makeRateLimiter
 * @param sql if true, a mysql limiter is returned, false for memory limiter.
 * @param settings the libary configuration object with the next interface
 * @interface RateLimitSql
 * @interface RateLimitMermory
 * @param BlackWhiteList controll whenever to wrap the limiter in the libary BlackAndWhite list
 * @returns {RateLimiterMySQL | RateLimiterMemory | RLWrapperBlackAndWhite } 
 * MySql limiter or a memory limiter with optionally in a black/white list
 *
 * 
 * @see {@link ./jwtAuth/utils/limiters/rateLimit.js}
 * @see {@link https://github.com/animir/node-rate-limiter-flexible}
 * @example
 *   const limit = makeRateLimiter(true, false, {
 *    dbName: database Name,
 *    storeClient: pool,
 *    storeType  : 'mysql2',
 *    inMemoryBlockOnConsumed: 1,
 *    keyPrefix: 'login',
 *    points: 1,
 *    tableName: 'login',
 *    duration:  1, 
 *    blockDuration:  1800,  
 *    inMemoryBlockDuration: 1800 
 *  });
 *
 * @description
 * Build a union of limiters, make them work as one, and (optionally) wrap it with a black/white list.
 * @function unionLimiter
 * 
* @param {limiters} an array of limiters produced via makeRateLimiter() function.
* @param {blackWhiteList} wrap it with a black/white list.
* @returns {BlockableUnion | RLWrapperBlackAndWhite} RateLimiterUnion or RateLimiterUnion wrapped in RLWrapperBlackAndWhite
* @example 
* 
 *   const limit = makeRateLimiter(true, false, {
 *    dbName: database Name,
 *    storeClient: pool,
 *      ....
 *  });
 *   const limit2 = makeRateLimiter(true, false, {
 *    dbName: database Name,
 *    storeClient: pool,
 *      ....
 *  });
*  unionLimiter([limit, slowLimit ], false)
 *  
 */
export { makeRateLimiter, unionLimiter } from './jwtAuth/utils/limiters/rateLimit.js';


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
