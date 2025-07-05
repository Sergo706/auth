import { Request, Response, NextFunction } from "express";
import { hashPassword } from "../utils/hash.js";
import { newUser } from "../models/zodSignUpSchemas.js";
import { createUser } from "../models/createUser.js";
import { makeCookie } from "../utils/cookieGenerator.js";
import { getConfiguration } from "../config/configuration.js";
import { getLogger } from "../utils/logger.js";
import { validateSchema } from "../utils/validateZodSchema.js";
import { isDisposable } from "../utils/isEmailDisposable.js";
import { isValidDomain } from "../utils/DnsMxLookUp.js";
import { guard } from "../utils/limiters/utils/guard.js";
import { makeConsecutiveCache } from "../utils/limiters/utils/consecutiveCache.js";
import { getLimiters } from "../utils/limiters/protectedEndpoints/signupLimiter.js";


const consecutiveForIp = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 30);
const consecutiveForCompositeKey = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 60 * 24);
const consecutiveForEmail = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 60 * 24);

export const handleSignUp = async (req: Request, res: Response, next: NextFunction) => {
  const log = getLogger().child({service: 'auth', branch: 'classic', type: 'signup'});
  const { uniLimiterIp, uniLimiterComposite, emailLimiter } = getLimiters();
  log.info('Starting signup process...')
  const { jwt } = getConfiguration();

  if (!req.is('application/json')) {
    log.warn('Unexpected content type');
    res.status(400).json({error: 'Bad Request.'})
    return; 
  }

  if (!(await guard(uniLimiterIp, req.ip!, consecutiveForIp, 2, 'ip', log, res))) return;

  log.info('Validating data...')

  const result = await validateSchema(newUser, req.body, req, log);

if ("valid" in result) { 
    if (!result.valid && result.errors !== 'XSS attempt') {
       res.status(400).json(Object.assign({error: result.errors,  "banned": false }))
       return;
    }
    res.status(403).json({"banned": true})
    return; 
} 
 
  const validUserData = result.data

  const { Name , email, password, confirmedPassword, rememberUser, termsConsent } = validUserData!;
  const compositeKey = `${req.ip!}_${email}`;

  
  if (!(await guard(uniLimiterComposite, compositeKey, consecutiveForCompositeKey, 2, 'compositeKey', log, res))) return;
  
  const isValidEmailDomain = await isValidDomain(email, log);
  const realUserEmail = await isDisposable(email, log);
  
  if (!isValidEmailDomain) {
    log.warn('Invalid email domain');
    res.status(400).json({error: 'Please enter a valid email address.'});
    return; 
  }
  
  if (!realUserEmail) {
    log.warn('Disposable email detected');
    res.status(400).json({error: 'This email type is not allowed. Please enter your real email address.'});
    return; 
  }

  if (!(await guard(emailLimiter, email, consecutiveForEmail, 2, 'email', log, res))) return;

  const hashedPassword = await hashPassword(password, log)

  const done = {
      Name: Name,
      email: email,
      password: hashedPassword!,
      confirmedPassword: confirmedPassword,
      rememberUser: rememberUser,
      termsConsent: termsConsent
  }
  const canaryCookie = req.cookies.canary_id
  
    const makeNewUser = await createUser(canaryCookie, done);
    const { success, duplicate, accessToken, refreshToken } = makeNewUser;
   
  if (!success) {
   if (duplicate) {
    res.status(409).json({ ok: false, receivedAt: new Date().toISOString(), error: 'E-mail already registered' , banned: false});
    return;
    }
    res.status(500).json({ ok: false, receivedAt: new Date().toISOString(), error: 'server error', banned: false});
    return;
  }
      if (success) {
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
        domain: jwt.refresh_tokens.domain,
        path: '/'
        })
        res.status(201).json({ 
          ok: true,
          receivedAt: new Date().toISOString(),
          accessToken: accessToken,
          banned: false,
          accessIat: Date.now().toString()
        });
      return;
      };
      log.fatal('Unexpected error type')
      res.status(500).json({error: `Unexpected error type`});
      return;
};
