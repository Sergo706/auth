import { z } from "zod/v4";
import { makeSafeString } from "~~/utils/zodSafeStringMaker.js";

export const newApiTokenSchema = z.object({
    privilege: z.enum(["custom", "demo", "restricted", "protected", "full"]),
    name:  makeSafeString({ 
        min: 1,
        max: 50
    }),
    ipv4: z.array(z.ipv4()).optional(),
    prefix: makeSafeString({
        min: 2,
        max: 10
    }),
    expires: z.number().optional()
})



export const standardSchema = z.object({
    tokenId: z.coerce.number(),
    publicIdentifier: makeSafeString({
        min: 137,
        max: 137
    }),
    name: makeSafeString({ 
        min: 1,
        max: 50
    })
})


export const ipRestrictionUpdate = z.object({
 ...standardSchema.shape,
 ipv4: z.array(z.ipv4()).optional(),
})

export const privilegeUpdate = z.object({
 ...standardSchema.shape,
 newPrivilege: z.enum(["custom", "demo", "restricted", "protected", "full"]),
})

export const privilegeQ = z.enum(["custom", "demo", "restricted", "protected", "full"]);

export const reqParams = z.object({ 
    action: z.enum(
        [
             "new-token",
             "revoke",
             "metadata",
             "rotate",
             "ip-restriction-update",
              'privilege-update',
             'list-metadata'
        ]
    )
})