import type { AccessTokenPayload } from '../../accessTokens.ts';
import { LinkTokenPayload } from '../../jwtAuth/tempLinks.js';
declare global {
  namespace Express {
    export interface Request {
      user?: AccessTokenPayload;
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

