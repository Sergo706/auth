import { NextFunction, Request, Response } from 'express';
import { pool } from '../config/dbConnection.js';
import { ResultSetHeader, RowDataPacket } from "mysql2";
import crypto from 'crypto';
import { code } from '../models/zodSchema.js'
import { generateRefreshToken, revokeRefreshToken, verifyRefreshToken } from '../../refreshTokens.js';
import { generateAccessToken } from '../../accsessTokens.js';
import { config } from '../config/secret.js';
import { makeCookie } from '../utils/cookieGenerator.js';
import { logger } from '../utils/logger.js';
import { validateSchema } from '../utils/validateZodSchema.js';
import { guard } from "../utils/limiters/utils/guard.js";
import { uniLimiter, resetCompositeKey, ipLimit  } from "../utils/limiters/protectedEndpoints/tempPostRoutesLimiter.js";
import { makeConsecutiveCache } from "../utils/limiters/utils/consecutiveCache.js"


const consecutiveForSlowDown = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 10);
export const consecutiveForjti = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 20);
const consecutiveForsubmittedHash = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 10);

export async function verifyMFA (req: Request, res: Response, next: NextFunction) {
  const log = logger.child({service: 'auth', branch: 'mfa', visitorId: req.newVisitorId ?? req.link.visitor})
   
  log.info(`Verifing mfa code...`)

 if (!req.is('application/json')) {
    log.warn('Content type is not json!')
    res.status(400).json({error: 'Bad Request.'})
    return; 
  }

  if (req.link.purpose !== "MFA" || req.link.subject !== 'MAGIC_LINK_MFA_CHECKS') {
    log.warn('Invalid link purpose')
     res.status(400).json({ error: "Invalid link purpose" });
    return;
  }


 if (!(await guard(uniLimiter, req.ip!, consecutiveForSlowDown, 2, 'SlowDown', log, res))) return;
 if (!(await guard(uniLimiter, req.link.jti!, consecutiveForjti, 1,'jti', log, res))) return;

 const result = await validateSchema(code, req.body, req, log)

 if ("valid" in result) { 
     if (!result.valid && result.errors !== 'XSS attempt') {
        res.status(400).json(Object.assign({error: result.errors,  "banned": false }))
        return;
     }
     res.status(403).json({"banned": true})
     return; 
 } 

  const validetedCode = result.data!.code;
  const submittedHash = crypto.createHash("sha256").update((validetedCode as any)).digest("hex");

  if (!(await guard(ipLimit, submittedHash, consecutiveForsubmittedHash, 1,'submittedHash', log, res))) return;

  if (!req.link.jti) {
    log.warn(`No Session Token`)
    res.status(500).json({ error: 'No Session Token' });
    return;
  }

const conn = await pool.getConnection();
try { 
   await conn.beginTransaction();
 const [rows] = await conn.execute<RowDataPacket[]>(`
    SELECT token, user_id 
      FROM mfa_codes
       WHERE jti        = ?
         AND code_hash  = ?
         AND expires_at > NOW()
         AND used       = 0
      FOR UPDATE
    `,[req.link.jti, submittedHash])

    if (!rows || rows.length === 0) {
    log.warn(`Invalid or expired code.`)
    await conn.rollback();
    res.status(401).json({ error: 'Invalid or expired code.' });
    return;
    }

 const [DELETE] = await conn.execute<ResultSetHeader>(`
      DELETE FROM mfa_codes
       WHERE jti        = ?
         AND user_id    = ?
         AND code_hash  = ?
         AND expires_at > NOW()
         AND used       = 0
      LIMIT 1
    `,[req.link.jti, rows[0].user_id, submittedHash])
       
    if (DELETE.affectedRows !== 1) {
    log.warn(`Invalid or expired code.`)
    await conn.rollback();
    res.status(401).json({ error: 'Invalid or expired code.' });
    return;
    }
   await ipLimit.block(submittedHash, 60 * 10);

  log.info(`Found valid code, updating users and visitors...`)
const currentVisitorId = req.newVisitorId || req.link.visitor;

  if (!currentVisitorId ) {
    log.fatal(`currentVisitorId  is empty, possible loop`)
    res.status(500).json({error: `currentVisitorId  is empty, possible loop`});
    return;
} 
    await conn.execute(`
  UPDATE users
  JOIN visitors
    ON visitors.visitor_id = ?
  SET
    users.visitor_id     = visitors.visitor_id,
    users.last_mfa_at    = NOW(),
    visitors.proxy_allowed   = 1,
    visitors.hosting_allowed = 1
  WHERE
    users.id = ?
  `,
    [currentVisitorId, rows[0].user_id]    
  );

  await uniLimiter.block(req.link.jti, 60 * 20);
  await conn.commit();
  consecutiveForSlowDown.delete(req.ip!);
  consecutiveForjti.delete(req.link.jti!);
  consecutiveForsubmittedHash.delete(submittedHash!);
  await resetCompositeKey(req.ip!);

 log.info(`updated users and visitors, generating tokens...`)
  const token = rows[0].token;
  const userId = rows[0].user_id;


  const result = await verifyRefreshToken(token, true);
  if (!result.valid) {
    log.warn(`invalid refresh token: ${result.reason}`)
     res.status(401).json({ error: result.reason });
    return;
  }
  
   const {success} = await revokeRefreshToken(token, true);
   
    if (!success) {
      log.error(`Error Revoking refresh token`)
    res.status(500).json({ error: `Error Revoking refresh token` });
    return;
    }

  const accessToken = generateAccessToken({
    id:         userId,
    visitor_id: currentVisitorId,
    jti: crypto.randomUUID() 
  });
  
    const newRefresh = await generateRefreshToken(
    config.auth.jwt.refresh_ttl,
    userId
  );

  makeCookie(res, 'iat', Date.now().toString(), {
      httpOnly: true,
      secure:   true,
      sameSite: 'strict',
      path:     '/',
      expires: newRefresh!.expiresAt,
      });

  makeCookie(res, 'session', newRefresh!.raw, {
     httpOnly: true,
     sameSite: "strict", 
     expires: newRefresh!.expiresAt,
     secure: true,
     domain: config.auth.jwt.domain,
     path: '/'
  })
    log.info(`MFA Verified! and new tokens are set`)
    res.status(200).json({ accessToken: accessToken, accessIat: Date.now().toString() });
    return;

} catch(err) {
    await conn.rollback();
    log.error({err},`MFA verify error`)
    res.status(500).json({ error: 'Internal server error' });
    return;
} finally {
  conn.release();
}
}