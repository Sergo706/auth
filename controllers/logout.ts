import { Request, Response } from "express";
import { revokeRefreshToken, verifyRefreshToken } from "../refreshTokens.js";
import { config } from "../../../config/secret.js";

export const handleLogout = async (req: Request, res: Response) => {
 const rawRefreshToken = req.cookies.session;
try {
 const result = await verifyRefreshToken(rawRefreshToken);
    
        if (result.valid) {
          const markToken = await revokeRefreshToken(rawRefreshToken);
            if (markToken.success) {
                res.clearCookie('session', {
                    httpOnly: true,
                    sameSite: "strict", 
                    secure: true,
                    domain: config.auth.jwt.domain,
                    path: '/'
                });
                res.status(200).json({session: 'Session deleted succesfuly!', userID: result.userId})
                return;
            }
        };

        if (!result.valid) {
             res.clearCookie('session', {
             httpOnly: true,
             sameSite: "strict", 
             secure: true,
             domain: config.auth.jwt.domain,
             path: '/'
            });
             res.clearCookie('iat', {
             httpOnly: true,
             sameSite: "strict", 
             secure: true,
             domain: config.auth.jwt.domain,
             path: '/'
            });
            res.status(200).json({session: 'No refresh record are found, but cookie was deleted'})
            return;
        };
  } catch(err) {
        console.error('Error login out');
        res.status(500).json({session: 'Error login out'})
  }  
}
