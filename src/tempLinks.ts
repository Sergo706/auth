import  jwt , { JwtPayload } from "jsonwebtoken";
import { config } from "./jwtAuth/config/secret.js";
import { logger } from "./jwtAuth/utils/logger.js";

const key = config.auth.jwt.magicLinks;
const { TokenExpiredError, JsonWebTokenError } = jwt;

export interface LinkTokenPayload {
  visitor: number;
  subject: string;
  purpose: "PASSWORD_RESET" | "MFA";
  jti?: string;
}

const log = logger.child({service: 'auth', branch: 'tempLinks', type: 'signature'})
export function tempJwtLink (payload: LinkTokenPayload): string {
log.info({payload},`Generating link signature...`)
const token = jwt.sign(payload, key!, {
   algorithm: 'HS512',
   expiresIn: '20m',
   subject: payload.subject,
   issuer: payload.purpose,
   audience:   `https://${config.auth.jwt.domain}`,
})
log.info({payload},`Generated link signature`)
return token;
}


export function verifyTempJwtLink (token: string, purpose: string, subject: string): 
{valid: boolean, payload?: JwtPayload, errorType?: string} {
log.info(`verifing link signature`)
try {
    const check = jwt.verify(token, key!, {
         algorithms: ['HS512'],
         issuer: purpose,
         subject: subject,
         audience:   `https://${config.auth.jwt.domain}`,
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
