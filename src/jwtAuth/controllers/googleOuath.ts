import { NextFunction, Request, Response } from "express"; 
import { googleAuth } from "../models/zodSchemaGoogle.js";
import { createOauthUser } from "../models/createOauthUser.js";
import { makeCookie } from "../utils/cookieGenerator.js"
import { config } from "../config/secret.js";
import { findUserByProvider } from "../models/findUserByProvider.js";
import { IssuedRefreshToken } from "../../refreshTokens.js";
import { logger } from "../utils/logger.js";
import { makeConsecutiveCache } from "../utils/limiters/utils/consecutiveCache.js";
import { guard } from "../utils/limiters/utils/guard.js";
import { validateSchema } from "../utils/validateZodSchema.js";
import { subLimiter, uniLimiter, compositeKeyLimiter } from "../utils/limiters/protectedEndpoints/ouathLimiters.js";

const consecutiveForIp = makeConsecutiveCache<{countData:number}>(2000, 1000 * 60 * 60 );
const consecutiveForSub = makeConsecutiveCache<{countData:number}>(2000, 1000 * 60 * 5 );
const consecutiveForCompositeKey = makeConsecutiveCache<{countData:number}>(2000, 1000 * 60 * 10 );

export const GoogleSignUp = async (req: Request, res: Response, next: NextFunction) => {
  const log = logger.child({service: 'auth', branch: 'oauth', visitorId: req.newVisitorId});



      if (!req.is('application/json')) {
        res.status(400).json({error: 'Bad Request.'})
        return; 
      }

  if (!(await guard(uniLimiter, req.ip!, consecutiveForIp, 1, 'ip', log, res))) return;

      log.info({body: req.body, cookies: req.cookies}, `Entered GoogleSignUp body`)
      const rawInfo = req.body.userInfo; 
      const result = await validateSchema(googleAuth, rawInfo, req, log);


      if ("valid" in result) { 
          if (!result.valid && result.errors !== 'XSS attempt') {
            res.status(400).json(Object.assign({error: result.errors,  "banned": false }))
            return;
          }
          res.status(403).json({"banned": true})
          return; 
      } 

        const validUserData = result.data!;
        const canaryCookie = req.cookies.canary_id;
        let accessToken: string, refreshToken: IssuedRefreshToken;
        const compositeKey = `${req.ip!}_${validUserData.sub}`;



        if (!(await guard(subLimiter, validUserData.sub, consecutiveForSub, 2, 'sub limiter', log, res))) return;
        if (!(await guard(compositeKeyLimiter, compositeKey, consecutiveForCompositeKey, 2, 'compositeKey', log, res))) return;

        log.info(`Calling findUserByProvider with id=', ${validUserData.sub}`)
        const found = await findUserByProvider('google', validUserData.sub);
        log.info({found: found.user},`findUserByProvider returned`)

      if(!found.user) { 
        log.info(`No existing user found, creating new one...`)
        const makeNewUser = await createOauthUser(canaryCookie, validUserData);
      if (!makeNewUser.success) {
        log.warn(`Failed to create new user. Server Error: 500`);
        if (makeNewUser.duplicate) {
            log.warn(`Founded duplicated user`)
            res.status(409).json({ ok: false, receivedAt: new Date().toISOString(), error: 'E-mail already registered' , banned: false});
            return;
            }
            res.status(500).json({ ok: false, receivedAt: new Date().toISOString(), error: 'server error', banned: false});
            return;
        }
            accessToken  = makeNewUser.accessToken!;
            refreshToken = makeNewUser.refreshToken!;
      } else {
            accessToken  = found.accessToken!;
            refreshToken = found.refreshToken!;
      }
          
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
            log.info(`User created / logged in succesfuly`);
            res.status(201).json({ 
              ok: true, 
              receivedAt: new Date().toISOString(),
              accessToken: accessToken,
              banned: false,
              accessIat: Date.now().toString()
            });
          
        return;
} 