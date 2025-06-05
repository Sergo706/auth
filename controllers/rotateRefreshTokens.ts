import { Request, Response } from "express";
import { verifyRefreshToken, generateRefreshToken } from "../refreshTokens.js";
import { makeCookie } from "../../../utils/cookieGenerator.js";
import { config } from "../../../config/secret.js";
import { strangeThings } from "../anomalies.js";

export const rotateRefreshTokens = async (req: Request, res: Response) => { 
        const rawRefreshToken = req.cookies.session;
        const canary_id = req.cookies.canary_id;

        try { 
         const anomalies = await strangeThings(rawRefreshToken, canary_id, req.ip!, req.get('User-Agent')!, false);

         if (!anomalies) {
           res.status(401).json({error: 'Token has been revoked, please login again1'});
          return;
         }
         
         const result = await verifyRefreshToken(rawRefreshToken);
         if (result.valid) {
            res.status(200).json({session: 'Refresh is up to date', userID: result.userId})
            return;
         }

        if (!result.valid && result.reason === 'Token not found') {
          res.status(401).json({error: 'Token not found'})
          return;
         }

         if (!result.valid && result.reason === 'Token has been revoked') {
          res.status(401).json({error: 'Token has been revoked, please login again'});
          return;
         }
   
        if (!result.valid && result.reason === 'Token expired') {
         
         if (typeof result.userId !== 'number') {
            res.status(500).json({ error: 'Missing user ID on expired token' });
            return; 
           }

           const newSession = await generateRefreshToken(config.auth.jwt.refresh_ttl, result.userId);
            makeCookie(res, 'iat', Date.now().toString(), {
                httpOnly: true,
                secure:   true,
                sameSite: 'strict',
                path:     '/',
                expires: newSession!.expiresAt,
                });
            makeCookie(res, 'session', newSession!.raw, {
               httpOnly: true,
               sameSite: "strict", 
               expires: newSession!.expiresAt,
               secure: true,
               domain: config.auth.jwt.domain,
              path: '/'
            })
           res.status(201).json({session: 'Refresh Token was expired and now is up to date', userID: result.userId})
          return;
        }
         if (!result.valid && result.reason === 'Unexpected Error') {
            res.status(500).json({ error: 'Server error validating refresh token' });
            return;
         } else { res.status(400).json({ error: 'Unexpected results Cannot rotate refresh token' });  return;}
         } catch(err) {
            console.warn(`Error Rotating refresh token: ${err}`)
            res.status(500).json({error: `Error Rotating refresh token: ${err}`})
            return;
         }
       }