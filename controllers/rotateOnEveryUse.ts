import { Request, Response } from 'express';
import { consumeAndVerifyRefreshToken, revokeRefreshToken, generateRefreshToken } from '../refreshTokens.js';
import { makeCookie } from '../../../utils/cookieGenerator.js';
import { config } from '../../../config/secret.js';
import { generateAccessToken } from '../accsessTokens.js';
import { strangeThings } from "../anomalies.js";

export const rotateCredentials = async (req: Request, res: Response) => {
  const rawRefreshToken = req.cookies.session;
  const canary_id = req.cookies.canary_id;
  
    try {
    const anomalies = await strangeThings(rawRefreshToken, canary_id, req.ip!, req.get('User-Agent')!, true);

    if (!anomalies) {
     res.status(401).json({error: 'Token has been revoked, please login again'});
     return;
 }
    const result = await consumeAndVerifyRefreshToken(rawRefreshToken);
    if (!result.valid) {
        res.status(401).json({ error: result.reason })
        return;
    };
    
 const revoke = await revokeRefreshToken(rawRefreshToken);

  if (!revoke.success) {
     res.status(500).json({ error: 'DB error revoking token' });
     return;
    } 

    const newRefresh = await generateRefreshToken(
      config.auth.jwt.refresh_ttl,
      result.userId!
    );

    const newAccess  = generateAccessToken({
      id: result.userId!,
      visitor_id: result.visitor_id!
    });

  makeCookie(res, 'iat', Date.now().toString(), {
    httpOnly: true,
    secure:   true,
    sameSite: 'strict',
    path:     '/',
    expires:  newRefresh.expiresAt
    });

  makeCookie(res, 'session', newRefresh.raw, {
      httpOnly: true,
      sameSite: 'strict',
      secure:   true,
      domain:   config.auth.jwt.domain,
      path:     '/',
      expires:  newRefresh.expiresAt
    });

     res.status(201).json({
      session:  'Refresh & access tokens rotated',
      accessToken: newAccess
    }) 
    return;
    

  } catch (err) {
    console.warn('Rotate-every-use failed:', err);
     res.status(500).json({ error: 'Server error rotating refresh token' })
    return;
  }
};

