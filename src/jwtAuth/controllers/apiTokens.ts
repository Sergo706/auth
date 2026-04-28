import { Request, Response } from "express";
import { RowDataPacket } from "mysql2";
import { createApiKey, getAllValidTokensList, privateActionManager } from "~/src/apiTokens.js";
import { getPool } from "~~/config/configuration.js";
import { getLogger } from "~~/utils/logger.js";
import { ipRestrictionUpdate, newApiTokenSchema, privilegeUpdate, reqParams, standardSchema } from "~~/models/apiTokensSchemas.js";
import { validateSchema } from "~~/utils/validateZodSchema.js";
import { guard } from "~/src/main.js";
import { getApiLimiters, resetApiUnionLimiters } from "~~/utils/limiters/protectedEndpoints/api.js";

export async function apiTokensController(req: Request, res: Response) {
    const log = getLogger().child({service: 'auth', branch: "api_tokens", type: 'routes'});
    const pool = getPool()
    
    if (!req.user) {
        log.warn(`Unauthorized access attempt`);
        res.status(401).json({
            authorized: false,
            reason: 'Not authenticated',
            ipAddress: req.ip,
            userAgent:  req.get("User-Agent"),
            date: new Date().toISOString()
        })
        return;
    }
    
     const { userId, visitor_id } = req.user;

     const paramsResult = await validateSchema(reqParams, req.params, req, log);
     if ("valid" in paramsResult) { 
        if (!paramsResult.valid && paramsResult.errors !== 'XSS attempt') {
            res.status(404).json({
                ok: false,
                date: new Date().toISOString(),
                reason: 'Not found'
            })
            return;
        }
        res.status(403).json({"banned": true})
        return; 
    }

    try {
          const [row] = await pool.execute<RowDataPacket[]>('SELECT * FROM users WHERE id = ?', [userId])
          const [rowVisitor] = await pool.execute<RowDataPacket[]>('SELECT * FROM visitors WHERE visitor_id = ?', [visitor_id])
    
          if (!row.length || !rowVisitor.length) {
             log.warn({user: req.user}, `Unauthorized access attempt, user ${userId} or visitor ${visitor_id} not found `)
             res.status(404).json({
                authorized: false,
                reason: 'Not found',
                ipAddress: req.ip,
                userAgent:  req.get("User-Agent"),
                date: new Date().toISOString()
            })
             return;
          } 
    
      } catch(error) {
        log.error(`Error validating user identity`)
        res.status(500).json({ authorized:false, reason:'Server error' })
        return;
      } 

      const { 
        newTokenCreationLimiter, 
        revokeTokensLimiter, 
        getMetadataTokenLimiter, 
        rotationRateLimiter, 
        ipRestrictionUpdate: ipRestrictionUpdateLimiter, 
        privilegeUpdate: privilegeUpdateLimiter,
        generalUnionLimiter, 
        cache 
    } = getApiLimiters()

      const { action } = paramsResult.data! 
      switch (action) {
         // public
         case 'new-token':
            if (!(await guard(generalUnionLimiter, req.ip!, cache.generalUnionLimiter, 1, 'new-token_general', log, res))) return;

            const results = await validateSchema(newApiTokenSchema, req.body, req, log);
            if ("valid" in  results) { 
                if (!results.valid && results.errors !== 'XSS attempt') {
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

            if (!(await guard(newTokenCreationLimiter, `${req.ip!}_${userId}`, cache.newTokenCreationLimiter, 2, 'new-token', log, res))) return;
            
            const { prefix, privilege, expires, ipv4, name } = results.data!;
            const newCreatedToken = await createApiKey(Number(userId), privilege, name, prefix, expires, ipv4);
            if (!newCreatedToken.ok) {
                res.status(newCreatedToken.reason ? 400 : 500).json({
                    ok: false,
                    date: newCreatedToken.date,
                    reason: newCreatedToken.reason ?? 'Internal Server Error'
                })
                return;
            }
            await resetApiUnionLimiters(req.ip!)
            res.status(201).json({
                ok: newCreatedToken.ok,
                date: newCreatedToken.date,
                data: newCreatedToken.data
            }) 
            return;
         
            // public
           case 'list-metadata':
                if (!(await guard(generalUnionLimiter, `${req.ip!}_list-metadata`, cache.generalUnionLimiter, 1, 'list-metadata_general', log, res))) return;
                
                if (req.method !== 'GET') {
                    res.status(400).json({
                        ok: false,
                        date: new Date().toISOString(),
                        reason: 'Bad Request'
                    })
                    return;
                }
                const validTokensList = await getAllValidTokensList(Number(userId));

                if (!validTokensList.ok) {
                    res.status(500).json({
                        ok: false,
                        date: validTokensList.date,
                        reason: validTokensList.reason
                    })
                    return;
                }
                
                res.status(200).json({
                    ok: validTokensList.ok,
                    date: validTokensList.date,
                    data: validTokensList.data
                })

                return;
            
                // private
        case 'ip-restriction-update':
                if (!(await guard(generalUnionLimiter, req.ip!, cache.generalUnionLimiter, 1, 'ip-restriction-update_general', log, res))) return;

                const ipRestrictionResults = await validateSchema(ipRestrictionUpdate, req.body, req, log);
                if ("valid" in ipRestrictionResults) { 
                    if (!ipRestrictionResults.valid && ipRestrictionResults.errors !== 'XSS attempt') {
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

                if (!(await guard(ipRestrictionUpdateLimiter, `${req.ip!}_${userId}`, cache.ipRestrictionUpdate, 2, 'ip-restriction-update', log, res))) return;

                const { ipv4: newIpv4, tokenId, name: tokenName, publicIdentifier: pubIdIp } = ipRestrictionResults.data!
                const newD = newIpv4 && newIpv4.length > 0 ? newIpv4 : null; 

                const ipUpdateResults = 
                await privateActionManager(Number(userId), tokenId, pubIdIp, tokenName, {
                    action: 'ip-restriction-update',
                    newIpAddress: newD
                });

                if (!ipUpdateResults.ok) {
                    res.status(400).json({
                        ok: ipUpdateResults.ok, 
                        date: ipUpdateResults.date,
                        reason: ipUpdateResults.reason,
                    })
                    return;
                }

                await resetApiUnionLimiters(req.ip!)
                res.status(200).json({
                    ok: ipUpdateResults.ok, 
                    date: ipUpdateResults.date,
                    data: ipUpdateResults.data
                })

                return;

            // private

         case 'privilege-update':
                    if (!(await guard(generalUnionLimiter, req.ip!, cache.generalUnionLimiter, 1, 'privilege-update_general', log, res))) return;

                    const privilegeResults = await validateSchema(privilegeUpdate, req.body, req, log);
                    if ("valid" in privilegeResults) { 
                        if (!privilegeResults.valid && privilegeResults.errors !== 'XSS attempt') {
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

                    if (!(await guard(privilegeUpdateLimiter, `${req.ip!}_${userId}`, cache.privilegeUpdate, 2, 'privilege-update', log, res))) return;

                    const { newPrivilege, name: privTokenName, tokenId: privTokenId, publicIdentifier: pubIdPriv } = privilegeResults.data!

                    const updatePrivilegesResults = 
                     await privateActionManager(Number(userId), privTokenId, pubIdPriv, privTokenName, {
                        action: 'privilege-update',
                        newPrivileges: newPrivilege
                     });
                    
                     if (!updatePrivilegesResults.ok) {
                            res.status(400).json({
                                ok: updatePrivilegesResults.ok,
                                date: updatePrivilegesResults.date, 
                                reason: updatePrivilegesResults.reason, 
                            })
                          return;
                     }
                     await resetApiUnionLimiters(req.ip!)
                     res.status(200).json({
                        ok: updatePrivilegesResults.ok,
                        date: updatePrivilegesResults.date, 
                        data: updatePrivilegesResults.data 
                     })
                    return;

         case 'revoke':

            if (!(await guard(generalUnionLimiter, req.ip!, cache.generalUnionLimiter, 1, 'revoke_general', log, res))) return;

            const revokeResults = await validateSchema(standardSchema, req.body, req, log);
            if ("valid" in revokeResults) { 
                if (!revokeResults.valid && revokeResults.errors !== 'XSS attempt') {
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

             if (!(await guard(revokeTokensLimiter, `${req.ip!}_${userId}`, cache.revokeTokensLimiter, 2, 'revoke', log, res))) return;
             
             const { name: revokeTokenName, tokenId: revokeTokenId, publicIdentifier: pubIdRevoke } = revokeResults.data!
             const revokeRes = await privateActionManager(Number(userId), revokeTokenId, pubIdRevoke, revokeTokenName, { action: 'revoke' });

             if (!revokeRes.ok) {
                 res.status(401).json({
                     ok: revokeRes.ok,
                     date: revokeRes.date,
                     reason: revokeRes.reason
                 })
                 return;
             }

             await resetApiUnionLimiters(req.ip!)
             res.status(200).json({
                 ok: revokeRes.ok,
                 date: revokeRes.date,
                 data: revokeRes.data
             })
     
             return;

         case 'metadata':

            if (!(await guard(generalUnionLimiter, req.ip!, cache.generalUnionLimiter, 1, 'metadata_general', log, res))) return;

            const metaDataResults = await validateSchema(standardSchema, req.body, req, log);
            if ("valid" in metaDataResults) { 
                if (!metaDataResults.valid && metaDataResults.errors !== 'XSS attempt') {
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

            if (!(await guard(getMetadataTokenLimiter, `${req.ip!}_${userId}`, cache.getMetadataTokenLimiter, 2, 'metadata', log, res))) return;

            const { name: metaTokenName, tokenId: metaTokenId, publicIdentifier: pubIdMeta } = metaDataResults.data!
            const metaDataRes = await privateActionManager(Number(userId), metaTokenId, pubIdMeta, metaTokenName, { action: 'metadata' });

            if (!metaDataRes.ok) {
                 res.status(401).json({
                     ok: metaDataRes.ok,
                     date: metaDataRes.date,
                     reason: metaDataRes.reason
                 })
                 return;
             }

             await resetApiUnionLimiters(req.ip!)
             res.status(200).json({
                 ok: metaDataRes.ok,
                 date: metaDataRes.date,
                 data: metaDataRes.data
             })
            return;

         case 'rotate': 
                if (!(await guard(generalUnionLimiter, req.ip!, cache.generalUnionLimiter, 1, 'rotate_general', log, res))) return;

                const rotationResults = await validateSchema(standardSchema, req.body, req, log);

                if ("valid" in rotationResults) { 
                    if (!rotationResults.valid && rotationResults.errors !== 'XSS attempt') {
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
                
                if (!(await guard(rotationRateLimiter, `${req.ip!}_${userId}`, cache.rotationRateLimiter, 2, 'rotate', log, res))) return;

                const { name: prevTokenName, tokenId: prevTokenId, publicIdentifier: pubIdPrev } = rotationResults.data!
                const rotationRes = await privateActionManager(Number(userId), prevTokenId, pubIdPrev, prevTokenName, { action: 'rotate' })

                if (!rotationRes.ok) {
                    res.status(400).json({
                        ok: rotationRes.ok, 
                        date: rotationRes.date,
                        reason: rotationRes.reason,
                    })
                    return;
                }

                await resetApiUnionLimiters(req.ip!)
                res.status(200).json({
                    ok: rotationRes.ok, 
                    date: rotationRes.date,
                    data: rotationRes.data
                })

                return;

            default:
                res.status(400).json({
                    ok: false,
                    date: new Date().toISOString(),
                    reason: "Bad Request"
                })
                return;
      } 
}