import { config } from '../../config/secret.js';
import jwt, { JwtPayload } from 'jsonwebtoken';
import crypto from 'crypto'

const { TokenExpiredError, JsonWebTokenError } = jwt;
export interface AccessTokenPayload {
  sub: number;
  visitor: number;
}

const key = config.auth.jwt.jwt_secret!;


export function generateAccessToken(user: {id: number, visitor_id: number}): string {
  const jti = crypto.randomUUID();

const payload : AccessTokenPayload = {
  sub: user.id,
  visitor: user.visitor_id
}

const token = jwt.sign(payload, key, { 
algorithm: 'HS512',
expiresIn: '15m',
jwtid: jti,
audience: 'api.riavzon.com2',
issuer: 'auth.riavzon.com2',
})

return token;
};



export function verifyAccessToken(token: string): {valid: boolean, payload?: JwtPayload, errorType?: string} {

  try {
   const check = jwt.verify(token, key, {
     algorithms: ['HS512'],
     audience: 'api.riavzon.com2',
     issuer: 'auth.riavzon.com2',
    })
    console.log('valid:', check);

   if (typeof check === "string") { 
         return { valid: false, errorType: "InvalidPayloadType" };
   }

    return {valid: true, payload: check };

  } catch (err) {
    if (!(err instanceof Error)) {
    console.warn('Unexpected error type:', err);
    return {valid: false, errorType: `Unexpected error type`};
  } 
    if (err instanceof TokenExpiredError) {
    console.warn('JWT expired at:', err.expiredAt);
    return {valid: false, errorType: `TokenExpiredError`};
  }
    if (err instanceof JsonWebTokenError) {
    console.warn('JWT error:', err.message);
      switch (err.message) {
        case 'invalid token':
          return {valid: false, errorType: `invalid token`};
        case 'jwt malformed': 
          return {valid: false, errorType: `jwt malformed`};
        case 'jwt signature is required': 
          return {valid: false, errorType: `jwt signature is required`};
        case 'invalid signature':
          return {valid: false, errorType: `invalid signature`};
        default:
          return {valid: false, errorType: `JsonWebTokenError`};
      }
  }

  }
console.warn('Unknown JWT verification error');
return {valid: false, errorType: `Unexpected error type` };
}