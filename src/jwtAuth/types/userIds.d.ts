import type { AccessTokenPayload } from '../../accessTokens.ts';
import { LinkTokenPayload } from '../../jwtAuth/tempLinks.js';
import type { JwtPayload } from 'jsonwebtoken';
declare global {
  namespace Express {
    export interface Request {
      /**
       * Authenticated user context populated by `protectRoute`.
       * Includes the decoded JWT payload for observability and authorization.
       *
       * Fields:
       * - `userId`: subject identifier (may be undefined for anonymous flows).
       * - `visitor_id`: numeric or string visitor identifier.
       * - `accessTokenId`: access token `jti` (may be undefined).
       * - `roles`: array of role names, if present in the token.
       * - `payload`: original decoded JWT payload.
       */
      user?: {
              userId: string | undefined,         
              visitor_id: string,
              accessTokenId: string | undefined,  
              roles?: string[],
              payload: JwtPayload
      };
      link: {     
      visitor: number,  
      subject: string,
      purpose: 'PASSWORD_RESET' | 'MFA' | string,
      jti?: string;
      }
      newVisitorId?: number;
    }
  }
}
