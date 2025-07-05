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

const log = getLogger().child({service: 'auth', branch: 'tempLinks', type: 'signature'})
export function tempJwtLink (payload: LinkTokenPayload): string {
const { magic_links } = getConfiguration(); 

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


export function verifyTempJwtLink (token: string, purpose: string, subject: string, jti: string): 
{valid: boolean, payload?: JwtPayload, errorType?: string} {
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
