import * as z from "zod";
import { ZodType } from 'zod/v4';
import type { BotDetectorConfigInput } from "@riavzon/bot-detector"
import mysql from "mysql2/promise";

let mainPool: mysql.PoolOptions;
let limiterPool: mysql.PoolOptions;


const store = z.strictObject({
 main: z.custom<mysql.PoolOptions>(
    (val): val is typeof mainPool =>
      typeof val === 'object' &&
      val !== null &&
      typeof (val as mysql.PoolOptions).host === 'string',
    { message: 'Expected a mysql2 config' }
  ),

 rate_limiters_pool: z.object({
    store: z.custom<mysql.PoolOptions>((val): val is typeof limiterPool => { 
        return (
            typeof val === 'object' &&
            val !== null &&
            typeof (val as mysql.PoolOptions).host === 'string'
        );
    }, { message: 'Expected a mysql2 config' }),

    dbName: z.string(),
}).required().strict(), 
}).required().strict();




export const configurationSchema = z.strictObject({
    store: store,
    service: z.object({
      Hmac: z.object({
         sharedSecret: z.string(),
         clientId: z.string(),
         maxClockSkew: z.number(),
      }).optional(),
      
      proxy: z.object({
         trust: z.boolean(),
         ipToTrust: z.string(),
         server: z.string().optional(),
      }),
      
      port: z.number().optional(),
      ipAddress: z.string().optional(),
      clientIp: z.string().optional(),
    }).optional(),

    password: z.object({
      pepper: z.string(),
      hashLength: z.number().optional(),
      timeCost: z.number().optional(),
      memoryCost: z.number().optional(),
    }),
   
    botDetector: z.discriminatedUnion("enableBotDetector", [
      z.object({
         enableBotDetector: z.literal(false)
      }),
      z.object({
         enableBotDetector: z.literal(true),
         settings: z.custom<BotDetectorConfigInput>().optional()
      })
 ]),
 htmlSanitizer: z.object({
      /** 
       * The number of time to run the sanitizer in a loop before breaking.
       * keep number high but not to high to prevent ddos.
       * default 50
       * */
      IrritationCount: z.number().default(50),
      maxAllowedInputLength: z.number().default(50000)
   }),
  magic_links: z.object({
    jwt_secret_key: z.string(),
    expiresIn: z.union([z.string(), z.number()]).optional(),
    expiresInMs: z.number().optional(),
    /** 
    * Full domain name, including the protocol
    * @example https://example.com.
    * @example https://localhost
    */
    domain: z.url({protocol: /^https?$/, normalize: false}),
    maxCacheEntries: z.number().optional(),
    thresholds: z.object({

         adaptiveMfa: z.object({
            allowedPerSuccessfulGet: z.number().default(5),
            allowedPerSuccessfulPost: z.number().default(3)   
         }).prefault({}),

         linkPasswordVerification: z.object({
            allowedPerSuccessfulGet: z.number().default(5),
            allowedPerSuccessfulPost: z.number().default(3)   
         }).prefault({}),

         customMfaFlowsAndEmailChanges: z.object({
            allowedPerSuccessfulGet: z.number().default(5),
            allowedPerSuccessfulPost: z.number().default(3)   
         }).prefault({}),
      }).prefault({}),

      linkToResetPasswordPage: z.url().default('https://localhost/accounts'),
      emailImages: z.object({
         otp: z.object({
            bannerImage: z.url().default('https://media.riavzon.com/otp/image-1.png'),
            device_image: z.url().default('https://media.riavzon.com/otp/image-2.png'),
            location_image: z.url().default('https://media.riavzon.com/otp/image-3.png'),
            date_image: z.url().default('https://media.riavzon.com/otp/image-4.png'),
         }).prefault({}),

         notificationBanner: z.url().default('https://media.riavzon.com/notifications/image-1.gif')
      }).prefault({}),
      
    paths: z.object({
       pathForCustomFlow: z.string().default('/auth/bounce'),
       pathForPasswordResetLink: z.string().default('/auth/bounce'),
       pathForAdaptiveMfaLink: z.string().default('/auth/bounce')
    }).prefault({}),

    notificationEmail: z.object({
         websiteName: z.string().default('Security Service'),
         privacyPolicyLink: z.url(),
         contactPageLink: z.url(),
         changePasswordPageLink: z.url(),
         loginPageLink: z.url()
    })
 }),  
    providers: z.array(
      z.union([
        z.object({
          name: z.string(),
          schema: z.instanceof(ZodType).transform(v => v as ZodType),
        }),
        z.object({
          name: z.string(),
          useStandardProfile: z.boolean().optional(),
          fields: z
            .record(
              z.string(),
              z.enum([
               'string','string?',
               'email','email?',
               'boolean','boolean?',
               'url','url?',
               'number','number?',
               'int','int?',
               'safeString','safeString?'
               ])
            )
            .optional(),
        }),
      ])
    ).optional(),

    /**
     * Trust the user device on successful logins.
     * Preventing the user to go through an MFA flow on login and expired canary_id Cookie.
     * @default false
     */
   trustUserDeviceOnAuth: z.boolean().default(false),
     
 jwt: z.object({
    jwt_secret_key: z.string(),
    access_tokens: z.object({
      expiresIn: z.union([z.string(), z.number()]).optional(),
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

    emailMfaLimiters: z.object({
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
      userIdLimiter: z.object({
           inMemoryBlockOnConsumed: z.number(),
           points: z.number(),
           duration: z.number(),
           blockDuration: z.number(),
           inMemoryBlockDuration: z.number()   
      }),
      globalEmailLimiter: z.object({
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
export type ConfigurationInput = z.input<typeof configurationSchema>;