import type { AccessTokenPayload } from '../../accessTokens.ts';
import { LinkTokenPayload } from '../../jwtAuth/tempLinks.js';
import type { JwtPayload } from 'jsonwebtoken';
declare global {
  namespace Express {
    export interface Request {
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
      purpose: 'PASSWORD_RESET' | 'MFA',
      jti?: string;
      }
      newVisitorId?: number;
    }
  }
}

