import { Request, Response } from "express";
import { getLogger } from "~~/utils/logger.js";
import { verifyApiKey } from "~/src/apiTokens.js";
import { guard } from "~/src/main.js";
import { getApiLimiters } from "~~/utils/limiters/protectedEndpoints/api.js";
import { privilegeQ } from "~~/models/apiTokensSchemas.js";
import z from "zod";
import { validateSchema } from "~~/utils/validateZodSchema.js";
import { resetApiUnionLimiters } from "~~/utils/limiters/protectedEndpoints/api.js";
import { resetLimiters } from "~/src/main.js";
import { fakeLogger } from "~~/utils/fakeLogger.js";
import { getConfiguration } from "~~/config/configuration.js";

export type Privileges = z.infer<typeof privilegeQ>;

export async function verifyApiTokenController(req: Request, res: Response) {
     const log = getLogger().child({service: 'auth', branch: "api_tokens", type: 'routes_verify'});
     const apiKey = req.get('x-api-key') ?? req.headers['X-API-KEY'];
     const providedIpAddress = req.ip;
     const requiredPrivilege = req.query.privilege as Privileges;
     
    const { 
        consumptionRateLimiter,
        generalUnionLimiter, 
        
        cache 
      } = getApiLimiters();
      
     const { rateLimitOnSuccessfulRequest } = getConfiguration().apiTokens;

    if (rateLimitOnSuccessfulRequest) {
        if (!(await guard(generalUnionLimiter, `${req.ip!}_verify`, cache.generalUnionLimiter, 1, 'ip', log, res))) return;
    }      
      
     if (!apiKey || typeof apiKey !== 'string') {
        if (!(await guard(consumptionRateLimiter, `${req.ip!}_verify`, cache.consumptionRateLimiter, 1, 'ip', log, res))) return;
        log.info('No api key is provided, or its malformed')
        res.status(401).json({
            ok: false,
            date: new Date().toISOString(),
            reason: 'No api key provided'
        })
        return;
     }

     if (!providedIpAddress || typeof providedIpAddress !== 'string') {
        if (!(await guard(consumptionRateLimiter, apiKey, cache.consumptionRateLimiter, 1, 'ip', log, res))) return;

        log.info({providedIpAddress}, 'Cant get client ip')
        res.status(400).json({
            ok: false,
            date: new Date().toISOString(),
            reason: 'Bad Request'
        })
        return;
     }

     const privilegesResults = await validateSchema(privilegeQ, requiredPrivilege, req, log);

     if ("valid" in privilegesResults) { 
         if (!privilegesResults.valid && privilegesResults.errors !== 'XSS attempt') {
             if (!(await guard(consumptionRateLimiter, apiKey, cache.consumptionRateLimiter, 2, 'ip', log, res))) return;
            res.status(400).json({
                ok: false,
                date: new Date().toISOString(),
                reason: 'Bad Request'
            })
            return;
        }
        res.status(403).json({"banned": true})
        return; 
    }
     
     const validatedPriv = privilegesResults.data!;
     const verifyRes = await verifyApiKey(apiKey, false, validatedPriv, false, false, providedIpAddress)

     if (!verifyRes.ok) {
          if (!(await guard(consumptionRateLimiter, apiKey, cache.consumptionRateLimiter, 1, 'ip', log, res))) return;
          if (!(await guard(consumptionRateLimiter, providedIpAddress, cache.consumptionRateLimiter, 2, 'ip', log, res))) return;
          res.status(401).json({
            ok: verifyRes.ok,
            date: verifyRes.date,
            reason: verifyRes.reason
        })
        return;
     }

     await resetApiUnionLimiters(`${req.ip!}_verify`);
     resetLimiters(fakeLogger, `${req.ip!}_verify`, [consumptionRateLimiter]);
     resetLimiters(fakeLogger, apiKey, [consumptionRateLimiter]);
     resetLimiters(fakeLogger, providedIpAddress, [consumptionRateLimiter]);

     res.status(200).json({
         ok: verifyRes.ok,
         date: verifyRes.date,
         data: verifyRes.data
     })
    return;
}