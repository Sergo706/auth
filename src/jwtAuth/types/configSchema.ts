import * as z from "zod";
import type { Pool as PromisePool } from 'mysql2/promise'
import { Pool as CallbackPool } from 'mysql2';
import { ZodType } from 'zod/v4';

let mainPool: PromisePool;
let limiterPool: CallbackPool;


const store = z.strictObject({
 main: z.custom<PromisePool>(
    (val): val is typeof mainPool =>
      typeof val === 'object' &&
      val !== null &&
      typeof (val as PromisePool).getConnection === 'function',
    { message: 'Expected a mysql2/promise Pool (must have getConnection())' }
  ),

 rate_limiters_pool: z.object({
    store: z.custom<CallbackPool>((val): val is typeof limiterPool => { 
        return (
            typeof val === 'object' &&
            val !== null &&
            typeof (val as CallbackPool).getConnection === 'function'
        );
    }, { message: 'Expected a mysql2 Pool (callback API)' }),

    dbName: z.string(),
}).required().strict(), 
}).required().strict();

export const configurationSchema = z.strictObject({
    store: store,
    telegram: z.object({
       token: z.string(),
       allowedUser: z.string().optional(),
       chatID: z.string().optional(),
    }),
    password: z.object({
      pepper: z.string(),
      hashLength: z.number().optional(),
      timeCost: z.number().optional(),
      memoryCost: z.number().optional(),
    }),
magic_links: z.object({
    jwt_secret_key: z.string(),
    expiresIn: z.number().optional(),
    expiresInMs: z.number().optional(),
    /** 
    * Full domain name, including the protocol
    * @example https://example.com.
    */
    domain: z.url({protocol: /^https?$/, hostname: z.regexes.domain, normalize: true}),
    maxCacheEntries: z.number().optional()
 }),  
    providers: z.array( 
    z.object({
      name: z.string(), 
      schema: z.instanceof(ZodType).transform(v => v as ZodType),
   })
).optional(),
    
     
 jwt: z.object({
    jwt_secret_key: z.string(),
    access_tokens: z.object({
      expiresIn: z.number().optional(),
      expiresInMs: z.number().optional(),
      algorithm: z.enum(["HS256", "HS384", "HS512", "RS256", "RS384",  "RS512", "ES256", "ES384", "ES512", "PS256" ,"PS384" , "PS512" ]).optional(),
      audience: z.string().optional(),
      issuer: z.string().optional(),
      subject: z.string().optional(),
      jwtid:   z.string().optional(),
      maxCacheEntries: z.number().optional(),
      payload: z.record(z.string(), z.unknown()).optional(),
    }),
    refresh_tokens: z.object({
        /** 
       * When true, every attempt to get a new access token when expired, will verify, and invalidate the refresh token, 
       * and produce fresh access and refresh token.
       */
       rotateOnEveryAccessExpiry: z.boolean(),
             /** 
       * Time in ms for the token to be considered valid.
       */
       refresh_ttl: z.number(),
      /** 
       * Your domain
       * @example example.com.
       */
       domain: z.string(),
      /** 
       * The maximum allowed active and valid refresh tokens (sessions) for a user.
       */
       MAX_SESSION_LIFE: z.number(),
       maxAllowedSessionsPerUser: z.number(),
       /** 
       * Bypass MFA for the specified period of time in ml,
       * if maxAllowedSessionsPerUser is exceeded for a certain user, and if a user.
       *
       */
       byPassAnomaliesFor: z.number(),
    })
 }),
    email: z.object({
        resend_key: z.string(),
        email: z.string()
    }),
    
    rate_limiters: z.object({
        linkVerificationLimiter: z.object({
            unionLimiter: z.object({
                burstLimiter: z.object({
                        inMemoryBlockOnConsumed: z.number(),
                        points: z.number(),
                        duration: z.number(),
                        blockDuration: z.number(),
                        inMemoryBlockDuration: z.number()  
                }),
                slowLimiter: z.object({
                        inMemoryBlockOnConsumed: z.number(),
                        points: z.number(),
                        duration: z.number(),
                        blockDuration: z.number(),
                        inMemoryBlockDuration: z.number()
                })
            })
        }).optional(),

        loginLimiters: z.object({
            unionLimiter: z.object({ 
                burstLimiter: z.object({
                    inMemoryBlockOnConsumed: z.number(),
                    points: z.number(),
                    duration: z.number(),
                    blockDuration: z.number(),
                    inMemoryBlockDuration: z.number()
                }),
                slowLimiter: z.object({
                    inMemoryBlockOnConsumed: z.number(),
                    points: z.number(),
                    duration: z.number(),
                    blockDuration: z.number(),
                    inMemoryBlockDuration: z.number()
                })

            }),
           ipLimiter: z.object({
             inMemoryBlockOnConsumed: z.number(),
             points: z.number(),
             duration: z.number(),
             blockDuration: z.number(),
             inMemoryBlockDuration: z.number()
           }),
           emailLimiter: z.object({
              inMemoryBlockOnConsumed: z.number(),
              points: z.number(),
              duration: z.number(),
              blockDuration: z.number(),
              inMemoryBlockDuration: z.number()
           })

        }).optional(),

        oauthLimiters: z.object({
            unionLimiter: z.object({ 
                ipLimiterBrute: z.object({
                       inMemoryBlockOnConsumed: z.number(),
                        points: z.number(),
                        duration: z.number(),
                        blockDuration: z.number(),
                        inMemoryBlockDuration: z.number()  
                }),
                ipLimiterSlow: z.object({
                        inMemoryBlockOnConsumed: z.number(),
                        points: z.number(),
                        duration: z.number(),
                        blockDuration: z.number(),
                        inMemoryBlockDuration: z.number()  
                })
            }),

            subLimiter: z.object({
                 inMemoryBlockOnConsumed: z.number(),
                  points: z.number(),
                  duration: z.number(),
                  blockDuration: z.number(),
                  inMemoryBlockDuration: z.number()
            }),
            compositeKeyLimiter: z.object({
                 inMemoryBlockOnConsumed: z.number(),
                  points: z.number(),
                  duration: z.number(),
                  blockDuration: z.number(),
                  inMemoryBlockDuration: z.number()
            })
        }).optional(),

    signupLimiters: z.object({ 
          unionLimiters: z.object({ 
            uniLimiterIp: z.object({ 
              ipLimit: z.object({ 
                inMemoryBlockOnConsumed: z.number(),
                points: z.number(),
                duration: z.number(),
                blockDuration: z.number(),
                inMemoryBlockDuration: z.number()
              }),
              slowIpLimit: z.object({ 
                inMemoryBlockOnConsumed: z.number(),
                points: z.number(),
                duration: z.number(),
                blockDuration: z.number(),
                inMemoryBlockDuration: z.number()       
              }),
            }),
             uniLimiterComposite: z.object({ 
                compositeKeyLimit: z.object({ 
                inMemoryBlockOnConsumed: z.number(),
                points: z.number(),
                duration: z.number(),
                blockDuration: z.number(),
                inMemoryBlockDuration: z.number()                  
                }),
                slowCompositeKeyLimit: z.object({ 
                  inMemoryBlockOnConsumed: z.number(),
                  points: z.number(),
                  duration: z.number(),
                  blockDuration: z.number(),
                  inMemoryBlockDuration: z.number()                     
             })
          }),
        }),
        emailLimit: z.object({ 
           inMemoryBlockOnConsumed: z.number(),
           points: z.number(),
           duration: z.number(),
           blockDuration: z.number(),
           inMemoryBlockDuration: z.number() 
        })
    }),

    tempPostRoutesLimiters: z.object({
        unionLimiters: z.object({
             limit: z.object({
                inMemoryBlockOnConsumed: z.number(),
                points: z.number(),
                duration: z.number(),
                blockDuration: z.number(),
                inMemoryBlockDuration: z.number()  
             }),
             slowLimit: z.object({
                    inMemoryBlockOnConsumed: z.number(),
                    points: z.number(),
                    duration: z.number(),
                    blockDuration: z.number(),
                    inMemoryBlockDuration: z.number() 
             }),
        }),

        ipLimit: z.object({
           inMemoryBlockOnConsumed: z.number(),
           points: z.number(),
           duration: z.number(),
           blockDuration: z.number(),
           inMemoryBlockDuration: z.number()   
        }),


    }).optional(),

    tokenLimiters: z.object({ 
      unionLimiters: z.object({ 
        refreshAccessTokenLimiter: z.object({  
        accessTokenBrute: z.object({ 
           inMemoryBlockOnConsumed: z.number(),
           points: z.number(),
           duration: z.number(),
           blockDuration: z.number(),
           inMemoryBlockDuration: z.number()           
        }),
        accessTokenSlow: z.object({ 
           inMemoryBlockOnConsumed: z.number(),
           points: z.number(),
           duration: z.number(),
           blockDuration: z.number(),
           inMemoryBlockDuration: z.number() 
        })
       }),
        refreshTokenLimiterUnion: z.object({  
        refreshTokenBrute: z.object({ 
           inMemoryBlockOnConsumed: z.number(),
           points: z.number(),
           duration: z.number(),
           blockDuration: z.number(),
           inMemoryBlockDuration: z.number()           
        }),
        refreshTokenSlow: z.object({ 
           inMemoryBlockOnConsumed: z.number(),
           points: z.number(),
           duration: z.number(),
           blockDuration: z.number(),
           inMemoryBlockDuration: z.number() 
        })
       }),

      }),
      refreshTokenLimiter: z.object({ 
           inMemoryBlockOnConsumed: z.number(),
           points: z.number(),
           duration: z.number(),
           blockDuration: z.number(),
           inMemoryBlockDuration: z.number()         
      }),
    }).optional(),


 initPasswordResetLimiters: z.object({
      unionLimiters: z.object({ 
        limit: z.object({
           inMemoryBlockOnConsumed: z.number(),
           points: z.number(),
           duration: z.number(),
           blockDuration: z.number(),
           inMemoryBlockDuration: z.number()   
        }),
        longLimiter: z.object({
           inMemoryBlockOnConsumed: z.number(),
           points: z.number(),
           duration: z.number(),
           blockDuration: z.number(),
           inMemoryBlockDuration: z.number()   
        })

      }),
      ipLimiter: z.object({
           inMemoryBlockOnConsumed: z.number(),
           points: z.number(),
           duration: z.number(),
           blockDuration: z.number(),
           inMemoryBlockDuration: z.number()   
      }),
      emailLimiter: z.object({
           inMemoryBlockOnConsumed: z.number(),
           points: z.number(),
           duration: z.number(),
           blockDuration: z.number(),
           inMemoryBlockDuration: z.number()   
      })

    }).optional(),

}).optional(),
logLevel: z.enum(['trace' , 'debug' , 'info' , 'warn' , 'error' , 'fatal']).optional()  

}).strict()

export type Configuration = z.infer<typeof configurationSchema>;