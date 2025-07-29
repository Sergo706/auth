import jwt, { JwtPayload } from 'jsonwebtoken';
import { getLogger } from './jwtAuth/utils/logger.js';
import { getConfiguration } from './jwtAuth/config/configuration.js';
import { tokenCache } from './jwtAuth/utils/accessTokentCache.js';

const { TokenExpiredError, JsonWebTokenError } = jwt;

interface AccessTokenPayload {
    id: number,
    visitor_id: number,
    jti: string,
    role?: string[]
  }
/**
 * @description
 * Generate a short-lived access token.
 *
 * @param {{ id: number; visitor_id: number; jti: string }} user
 *   The payload for the access token, containing:
 *   - `id`: the user’s unique identifier
 *   - `visitor_id`: the visitor’s session identifier
 *   - `jti`: a unique token identifier (JWT ID)
 *
 * @returns {string}
 *   A signed JWT access token string.
 *
 * @example
 * import { v4 as uuid } from "uuid";
 *
 * const user = { id: 1, visitor_id: 12, jti: uuid() };
 * const token = generateAccessToken(user);
 */
export function generateAccessToken(user: AccessTokenPayload): string {
  const { jwt: { jwt_secret_key, access_tokens, refresh_tokens } } = getConfiguration();
  const log = getLogger().child({service: 'auth', branch: 'access token'})

  const payload = {
    visitor: user.visitor_id,
    ...access_tokens.payload,
    roles: user.role ?? []
  }
  
  const token = jwt.sign(payload, jwt_secret_key, { 
    algorithm: access_tokens.algorithm ?? 'HS512',
    expiresIn: access_tokens.expiresIn ?? '15m',
    audience: access_tokens.audience ?? refresh_tokens.domain,
    issuer:   access_tokens.issuer ?? refresh_tokens.domain,
    subject: access_tokens.subject ?? user.id.toString(),
    jwtid:   access_tokens.jwtid ?? user.jti,
  })
  
tokenCache().set(token, { jti: user.jti, visitorId: user.visitor_id, userId: user.id,  roles: user.role ?? [], valid: true })
log.info({user},'Generated new access token')
return token;
};

/**
 * @description
 * Verify and decode a JWT access token.
 *
 * @param {string} token
 *   The JWT string to verify.
 * @param {import('./accessTokens.js').claims} Payload
 *   The expected payload shape/schema for validation.
 *
 * @returns {{ valid: boolean; payload?: JwtPayload; errorType?: string }}
 *   An object indicating verification success, the decoded payload if valid,
 *   or an error type if verification failed.
 *
 * @example
 * import { claims } from './accessTokens.js';
 *
 * const result = verifyAccessToken(token, claims);
 * if (result.valid) {
 *   console.log('Payload:', result.payload);
 * } else {
 *   console.error('Error verifying token:', result.errorType);
 * }
 *
 * @see {@link ./accessTokens.js}
 */
export function verifyAccessToken(token: string): {valid: boolean, payload?: JwtPayload, errorType?: string} {
const log = getLogger().child({service: 'auth', branch: 'access token'})
  log.info('Verifying access token...')
  const { jwt: { jwt_secret_key, access_tokens, refresh_tokens } } = getConfiguration();

  const cache = tokenCache().get(token);

  if (!cache || !cache.valid) {
      log.warn('InvalidPayloadType')
      log.warn(`Verify access token returned on missing cache/invalid cache`)
      return { valid: false, errorType: "InvalidPayloadType" };
   }

  try {
   const check = jwt.verify(token, jwt_secret_key, {
     algorithms: [access_tokens.algorithm ?? 'HS512'],
     audience: access_tokens.audience ?? refresh_tokens.domain,
     issuer: access_tokens.issuer ?? refresh_tokens.domain,
     subject: cache.userId as unknown as string,
     jwtid: cache.jti,
    }); 
    
    if (typeof check === "string") { 
      log.info('InvalidPayloadType')
      return { valid: false, errorType: "InvalidPayloadType" };
    }
    
    if (cache.visitorId !== check.visitor)  {
      log.error(`Jwt error: invalid visitor id`)
      return { valid: false, errorType: "Invalid visitor id" };
    }

    const provided = check.roles as string[];
    const requiredRoles = cache.roles; 

    if (provided && requiredRoles && requiredRoles.length > 0) {
      if (
        !Array.isArray(provided) ||
        !Array.isArray(requiredRoles) ||
        !provided.every((r: any) => typeof r === 'string') ||
        !requiredRoles.every((r: any) => typeof r === 'string')
        ) {
            log.error('Malformed roles claim', { roles: provided });
           return { valid: false, errorType: 'MalformedPayload' };
        }
        const missing = requiredRoles.filter(r => !provided.includes(r));

        if (missing.length > 0) {
          log.error('Roles mismatch', { required: requiredRoles, provided: provided, missing });
          return { valid: false, errorType: 'InvalidRoles' };
        }
        const extras = provided.filter(r => !requiredRoles.includes(r));
        if (extras.length > 0) {
          log.error('Unexpected roles', { extras });
          return { valid: false, errorType: 'InvalidRoles' };
        }
    }
  

    log.info({check},`access token verified:`)
    return {valid: true, payload: check };

  } catch (err) {
    if (!(err instanceof Error)) {
      log.error({err},`Unexpected error type`)
    return {valid: false, errorType: `Unexpected error type`};
  } 
    if (err instanceof TokenExpiredError) {
      log.error({err},`JWT expired at ${err.expiredAt}`)
      tokenCache().delete(token);
      return {valid: false, errorType: `TokenExpiredError`};
  }
    if (err instanceof JsonWebTokenError) {
     log.error({err},`JWT error`)
      switch (err.message) {
        case 'invalid token':
          log.error({err},`invalid token`)
          return {valid: false, errorType: `invalid token`};
        case 'jwt malformed': 
          log.error({err},`jwt malformed`)
          return {valid: false, errorType: `jwt malformed`};
        case 'jwt signature is required': 
           log.error({err},`jwt signature is required`)
          return {valid: false, errorType: `jwt signature is required`};
        case 'invalid signature':
          log.error({err},`invalid signature`)
          return {valid: false, errorType: `invalid signature`};
        default:
          log.error({err},`JsonWebTokenError`)
          return {valid: false, errorType: `JsonWebTokenError`};
      }
  }

  }
log.error(`Unknown JWT verification error`)
console.warn('Unknown JWT verification error');
return {valid: false, errorType: `Unexpected error type` };
}