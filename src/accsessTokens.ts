import { config } from './jwtAuth/config/secret.js';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { logger } from './jwtAuth/utils/logger.js';

const { TokenExpiredError, JsonWebTokenError } = jwt;
export interface claims {
  sub: string,
  visitor: number,
  jti: string
}

const key = config.auth.jwt.jwt_secret!;
 const log = logger.child({service: 'auth', branch: 'access token'})

export function generateAccessToken(user: {id: number, visitor_id: number, jti: string}): string {

const payload = {
  visitor: user.visitor_id,
}

const token = jwt.sign(payload, key, { 
algorithm: 'HS512',
expiresIn: '15m',
audience: 'api.riavzon.com2',
issuer: 'auth.riavzon.com2',
subject: user.id.toString(),
jwtid:    user.jti,
})

log.info({user},'Generated new access token')
return token;
};



export function verifyAccessToken(token: string, Payload: claims): {valid: boolean, payload?: JwtPayload, errorType?: string} {
log.info('Verifing access token...')
  try {
   const check = jwt.verify(token, key, {
     algorithms: ['HS512'],
     audience: 'api.riavzon.com2',
     issuer: 'auth.riavzon.com2',
     subject: Payload.sub,
     jwtid: Payload.jti,
    }); 
    
    if (typeof check === "string") { 
      log.info('InvalidPayloadType')
      return { valid: false, errorType: "InvalidPayloadType" };
    }
    
    if (Payload.visitor !== check.visitor)  {
      log.error(`Jwt error: invalid visitor id`)
      return { valid: false, errorType: "Invalid visitor id" };
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