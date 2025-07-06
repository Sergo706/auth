import  jwt , { JwtPayload } from "jsonwebtoken";
import { getLogger } from "./jwtAuth/utils/logger.js";
import { getConfiguration } from "./jwtAuth/config/configuration.js";


const { TokenExpiredError, JsonWebTokenError } = jwt;

export interface LinkTokenPayload {
  visitor: number;
  subject: string;
  purpose: "PASSWORD_RESET" | "MFA";
  jti?: string;
}


/**
 * @description
 * Generate a short-lived JWT link token for actions such as password resets, magic links, or MFA.
 *
 * @param {import('./types').LinkTokenPayload} payload
 *   The payload data for the link token, including:
 *   - `purpose`: the intended use (e.g., `'password-reset'`, `'magic-link'`, `'MFA'`)
 *   - `subject`: the subject identifier (e.g., user ID or email)
 *   - `jti`: a unique JWT ID
 *   - any other custom claims required by your application
 *
 * @returns {string}
 *   A signed JWT string representing the link token.
 *
 * @example
 * import { v4 as uuid } from 'uuid';
 * import { tempJwtLink } from './tempJwtLink.js';
 *
 * const payload = {
 *   purpose: 'password-reset',
 *   subject: 'user@example.com',
 *   jti: uuid(),
 *   // additional claims...
 * };
 * const token = tempJwtLink(payload);
 * console.log('Link token:', token);
 */
export function tempJwtLink (payload: LinkTokenPayload): string {
const { magic_links } = getConfiguration(); 
const log = getLogger().child({service: 'auth', branch: 'tempLinks', type: 'signature'})
log.info({payload},`Generating link signature...`)

const token = jwt.sign(payload, magic_links.jwt_secret_key, {
   algorithm:  'HS512',
   expiresIn: magic_links.expiresIn ?? '20m',
   subject: payload.subject,
   issuer: payload.purpose,
   audience:   `https://${magic_links.domain}`,
   jwtid: payload.jti
})
log.info({payload},`Generated link signature`)
return token;
}

/**
 * @description
 * Verify a short-lived JWT link used for password resets, magic links, MFA, etc.
 *
 * @param {string} token
 *   The JWT string to verify.
 * @param {string} purpose
 *   The intended purpose of the token (e.g., `'MFA'`, `'password-reset'`, `'magic-link'`).
 * @param {string} subject
 *   The subject of the token (e.g., user ID or email address).
 * @param {string} jti
 *   The JWT ID (`jti`) that must match the token’s claim.
 *
 * @returns {{
 *   valid: boolean;
 *   payload?: JwtPayload;
 *   errorType?: string;
 * }}
 *   An object indicating:
 *   - `valid`: whether the token is valid and unexpired  
 *   - `payload`: the decoded JWT payload if valid  
 *   - `errorType`: a string describing why verification failed, if any
 *
 * @example
 * import { v4 as uuid } from 'uuid';
 * 
 * const jti = uuid();
 * const result = verifyTempJwtLink(
 *   'eyJhbGciOiJI…',   // token
 *   'MFA',             // purpose
 *   'user@example.com',// subject
 *   jti                // jti
 * );
 * 
 * if (result.valid) {
 *   console.log('Token payload:', result.payload);
 * } else {
 *   console.error('Token error:', result.errorType);
 * }
 *
 * @see {@link ./tempJwtLink.js}
 */
export function verifyTempJwtLink (token: string, purpose: string, subject: string, jti: string): 
{valid: boolean, payload?: JwtPayload, errorType?: string} {
  const log = getLogger().child({service: 'auth', branch: 'tempLinks', type: 'signature'})
log.info(`verifing link signature`)
const { magic_links } = getConfiguration(); 
try {
    const check = jwt.verify(token, magic_links.jwt_secret_key!, {
         algorithms: ['HS512'],
         issuer: purpose,
         subject: subject,
         audience:   `https://${magic_links.domain}`,
         jwtid: jti
    })
    log.info({check},`verified signature`)


   if (typeof check === "string") { 
      log.warn(`InvalidPayloadType`)
         return { valid: false, errorType: "InvalidPayloadType" };
   }
   return {valid: true, payload: check };
  
} catch (err) {
    if (!(err instanceof Error)) {
    log.error({err}, `Unexpected error type`)
    return {valid: false, errorType: `Unexpected error type`};
  } 
    if (err instanceof TokenExpiredError) {
    log.error({err}, `JWT expired at ${err.expiredAt}`)
    return {valid: false, errorType: `TokenExpiredError`};
  }
    if (err instanceof JsonWebTokenError) {
    console.warn('JWT error:', err.message);
      switch (err.message) {
        case 'invalid token':
           log.error({err}, `invalid token`)
          return {valid: false, errorType: `invalid token`};
        case 'jwt malformed': 
          log.error({err}, `jwt malformed`)
          return {valid: false, errorType: `jwt malformed`};
        case 'jwt signature is required': 
          log.error({err}, `jwt signature is required`)
          return {valid: false, errorType: `jwt signature is required`};
        case 'invalid signature':
          log.error({err}, `invalid signature`)
          return {valid: false, errorType: `invalid signature`};
        default:
          log.error({err}, `JsonWebTokenError`)
          return {valid: false, errorType: `JsonWebTokenError`};
      }
  }
    log.fatal({err}, `Unknown JWT verification error`)
    console.warn('Unknown JWT verification error');
    return {valid: false, errorType: `Unexpected error type` };
  }

}
