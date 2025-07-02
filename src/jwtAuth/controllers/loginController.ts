import { Request, Response, NextFunction } from "express";
import { verifyPassword } from "../utils/hash.js";
import { validateSchema } from "../utils/validateZodSchema.js";
import { login } from "../models/zodLoginSchema.js";
import { pool } from "../config/dbConnection.js";
import { config } from "../config/secret.js";
import { logger } from "../utils/logger.js";
import { RowDataPacket } from "mysql2";
import { uniLimiter, resetLoginKey, ipLimiter, emailLimiter } from "../utils/limiters/protectedEndpoints/loginLimiter.js";
import { generateRefreshToken } from "../../refreshTokens.js";
import { generateAccessToken } from "../../accsessTokens.js";
import { makeCookie } from "../utils/cookieGenerator.js";
import { makeConsecutiveCache } from "../utils/limiters/utils/consecutiveCache.js";
import { guard } from "../utils/limiters/utils/guard.js";
import crypto from 'node:crypto'

const consecutiveForIp = makeConsecutiveCache< {countData:number} >(2000, 1000 * 24 * 60 * 60);
const consecutive429 = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 60);
const consecutiveForEmail = makeConsecutiveCache< {countData:number} >(2000, 1000 * 24 * 60 * 60);

export const handleLogin = async (req: Request, res: Response, next: NextFunction) => {

const log = logger.child({service: 'auth', branch: 'classic', type: 'login'});

log.info(`Validating data...`)

 
  if (!req.is('application/json')) {
    log.warn(`Content type is not json!`)
    res.status(400).json({error: 'Bad Request.'})
    return; 
  }

  if (!(await guard(ipLimiter, req.ip!, consecutiveForIp, 2, 'ip', log, res))) return;

 const result = await validateSchema(login, req.body, req, log)

if ("valid" in result) { 
    if (!result.valid && result.errors !== 'XSS attempt') {
       res.status(400).json(Object.assign({error: result.errors,  "banned": false }))
       return;
    }
    res.status(403).json({"banned": true})
    return; 
} 

const {email, password} = result.data;
const compositeKey = `${req.ip!}_${email}`;
if (!(await guard(emailLimiter, email, consecutiveForEmail, 2,'email', log, res))) return;
if (!(await guard(uniLimiter,  compositeKey, consecutive429, 3, 'ip+email', log, res))) return;

log.info(`Data parsed and sanitized, searching for user...`)
  const [user] = await pool.execute<RowDataPacket[]>(`
    SELECT visitor_id, password_hash AS hashed_password, id 
        FROM users
    WHERE email = ?
    AND active_user = 1
    LIMIT 1
    `,[email]);

    if (!user.length || user.length === 0) {
      log.warn(`User not found.`)
      res.status(401).json({ ok: false, error: 'Invalid email or password' });
      return;
    }

    const results = user[0]
    log.info(`Found user, validating password...`)
    const isPasswordValid = await verifyPassword(results.hashed_password, password);
    
    if (!isPasswordValid) {  
      log.warn(`Password is not found.`) 
     log.warn({ip: req.ip},`Invalid email or password entered`)
     res.status(401).json({ok: false, receivedAt: new Date().toISOString(), error: 'Invalid email or password'})
     return;
    };
    
    log.warn(`Credentials valid, generating tokens...`) 
    consecutiveForIp.delete(req.ip!);
    consecutive429.delete(compositeKey);
    consecutiveForEmail.delete(email)
    await resetLoginKey(compositeKey);

      const refreshToken = await generateRefreshToken(config.auth.jwt.refresh_ttl, results.id);
      const accessToken  = generateAccessToken({ id: results.id, visitor_id: results.visitor_id, jti: crypto.randomUUID() });

          makeCookie(res, 'iat', Date.now().toString(), {
            httpOnly: true,
            secure:   true,
            sameSite: 'strict',
            path:     '/',
            expires: refreshToken!.expiresAt,
            });

          makeCookie(res, 'session', refreshToken!.raw, {
            httpOnly: true,
            sameSite: "strict", 
            expires: refreshToken!.expiresAt,
            secure: true,
            domain: config.auth.jwt.domain,
            path: '/'
            })

            log.info({userId: results.id, visitorId: results.visitor_id}, `User logged in succesfuly`);
            res.status(200).json({ 
            ok: true, 
            receivedAt: new Date().toISOString(),
            accessToken: accessToken,
            banned: false,
            accessIat: Date.now().toString()
          });
            return;
}