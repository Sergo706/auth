import { NextFunction, Request, Response } from "express"; 
import { createOauthUser } from "../models/createOauthUser.js";
import { makeCookie } from "../utils/cookieGenerator.js"
import { getConfiguration } from "../config/configuration.js";
import { findUserByProvider } from "../models/findUserByProvider.js";
import { IssuedRefreshToken } from "../../refreshTokens.js";
import { getLogger } from "../utils/logger.js";
import { makeConsecutiveCache } from "../utils/limiters/utils/consecutiveCache.js";
import { guard } from "../utils/limiters/utils/guard.js";
import { validateSchema } from "../utils/validateZodSchema.js";
import { getLimiters } from "../utils/limiters/protectedEndpoints/oauthLimiters.js";
import { getProviders } from "../utils/newOauthProvider.js";
import { trustVisitor } from "../models/trustVisitor.js";
import { generateAccessToken } from "../../accessTokens.js";
import crypto from "crypto";
import { safeAction } from "@riavzon/utils";
import { fakeLogger } from "~~/utils/fakeLogger.js";

const consecutiveForIp = makeConsecutiveCache<{countData:number}>(2000, 1000 * 60 * 60 );
const consecutiveForSub = makeConsecutiveCache<{countData:number}>(2000, 1000 * 60 * 5 );
const consecutiveForCompositeKey = makeConsecutiveCache<{countData:number}>(2000, 1000 * 60 * 10 );

/**
 * Handle OAuth login/registration for a configured provider.
 *
 * Flow:
 * - Validates provider name from route param and input against provider schema.
 * - Applies IP/subject/composite-key rate limits.
 * - Finds or creates the user, issues refresh + access tokens, and sets cookies.
 *
 * Responses:
 * - 201: `{ ok, accessToken, accessIat }` with cookies set.
 * - 400: Bad request or schema validation errors.
 * - 404: Unknown provider.
 * - 409: E-mail already registered (duplicate on create path).
 * - 500: Server error during user creation or token issuance.
 */
export const OAuthHandler = async (req: Request, res: Response, next: NextFunction) => {
  const log = getLogger().child({service: 'auth', branch: 'oauth', visitorId: req.newVisitorId});
  const { uniLimiter, compositeKeyLimiter, subLimiter } = getLimiters();
  const { jwt, trustUserDeviceOnAuth } = getConfiguration();
  const providedName = req.params.providerName as string;
  const providers = getProviders()

      if (!req.is('application/json')) {
        res.status(400).json({error: 'Bad Request.'})
        return; 
      }

      if(!providedName || providers?.length === 0) {
        log.info(`Provider ${providedName} is not found.`)
        res.status(404).json({ok: false, receivedAt: new Date().toISOString(), error: "Not found", banned: false});  
        return;
      }

      if (!(await guard(uniLimiter, req.ip!, consecutiveForIp, 1, 'ip', log, res))) return;

      const matchedProvider = providers.find(e => e.provider.name === providedName);

      if (!matchedProvider) {
        log.info(`Provider ${providedName} is not configured.`)
        res.status(404).json({ok: false, receivedAt: new Date().toISOString(), error: "Not found", banned: false});  
        return;
      }

      log.info({body: req.body, cookies: req.cookies}, `Entered OAuth body`)
      const rawInfo = req.body.userInfo ?? req.body.user ?? req.body; 
      const result = await validateSchema(matchedProvider.provider.schema, rawInfo, req, log);


      if ("valid" in result) { 
          if (!result.valid && result.errors !== 'XSS attempt') {
            res.status(400).json(Object.assign({error: result.errors,  "banned": false }))
            return;
          }
          res.status(403).json({"banned": true})
          return; 
      } 

        const validUserData = result.data!;
        const userSchema = matchedProvider.mapProfile(validUserData)
        const canaryCookie = req.cookies.canary_id;
        let accessToken: string, refreshToken: IssuedRefreshToken;
        const userSub = String(userSchema.sub ?? userSchema.id ?? userSchema.user_id);
        const compositeKey = `${req.ip!}_${userSub}`;



        if (!(await guard(subLimiter, userSub!, consecutiveForSub, 2, 'sub limiter', log, res))) return;
        if (!(await guard(compositeKeyLimiter, compositeKey, consecutiveForCompositeKey, 2, 'compositeKey', log, res))) return;

        if (!userSchema || !userSub) {
          log.error({Schema: userSchema, providerId: userSub},`Schema is not valid or provider id is undefined!'`);
          res.status(500)
          .json({
            ok: false,
            receivedAt: new Date().toISOString(),
            error: "Schema is not valid or provider id is undefined!",
            banned: false});
          return;
        };

        log.info(`Calling findUserByProvider with id=', ${userSub}`)

        const found = await safeAction(`${canaryCookie}:${compositeKey}`, async () => {
            return await findUserByProvider(providedName, userSub);
        }, 6000, fakeLogger)

        log.info({found: found.user},`findUserByProvider returned`)

      if(!found.user) { 
        log.info(`No existing user found, creating new one...`)

        const makeNewUser = await safeAction(`${canaryCookie}:${compositeKey}`, async () => {
          return await createOauthUser(canaryCookie, userSchema, providedName);
        }, 6000, fakeLogger)

      if (!makeNewUser.success) {
        log.warn(`Failed to create new OAuth user for ${providedName}.`);
        if (makeNewUser.duplicate) {
            log.warn(`Founded duplicated user`)
            res.status(409).json({ ok: false, receivedAt: new Date().toISOString(), error: 'E-mail already registered' , banned: false});
            return;
          }

        if (makeNewUser.noCanaryCookie) {
            log.warn(`No fingerprint`)
            res.status(400).json({ok: false, receivedAt: new Date().toISOString(), error: 'No canary_id or visitor fingerprint in db!'});
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

            if (trustUserDeviceOnAuth && req.newVisitorId) {

              const trustUser = await safeAction(`${canaryCookie}:${compositeKey}:trust`, async () => {
                  return await trustVisitor(found.id!, req.newVisitorId!, req.cookies.canary_id, req.fingerPrint, log);
              }, 6000, fakeLogger)

                 if (trustUser.ok) {
                    accessToken = generateAccessToken({ id: found.id!, visitor_id: req.newVisitorId, jti: crypto.randomUUID() });
                 } else {
                  log.warn({reason: trustUser.data},`Failed to trust user device`) 
                 }
            }
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
            domain: jwt.refresh_tokens.domain,
            path: '/'
            })
            log.info(`User created / logged in successfully`);
            res.status(201).json({ 
              ok: true, 
              receivedAt: new Date().toISOString(),
              accessToken: accessToken,
              banned: false,
              accessIat: Date.now().toString()
            });
          
        return;
} 
