import type { AccessTokenPayload } from '../services/jwtAuth/accsessTokens.js';
import { LinkTokenPayload } from '../services/jwtAuth/tempLinks.js';
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

