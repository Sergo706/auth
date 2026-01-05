import jwt from 'jsonwebtoken'
import { ProviderConfig, JsonProviderSpec } from '../utils/newOauthProvider.js';
import { ZodType } from 'zod/v4';
import mysql2 from 'mysql2/promise';
import mysql from 'mysql2'; 

export interface AuthConfig {
  store: {
    main: mysql2.Pool,
    rate_limiters_pool: {
      store: mysql.Pool,
      dbName: string,
    }
  };
  telegram: {
    token:        string;
    allowedUser?: string;
    chatID?:      string;
  };
  password: {
      pepper: string;
      hashLength?: number;
      timeCost?: number;
      memoryCost?: number;
    },
    /** 
 * The number of time to run the sanitizer in a loop before breaking.
 * keep number high but not to high to prevent ddos.
 * default 50
 * */
  htmlSanitizerIrritationCount: number;
  magic_links: {
    jwt_secret_key: string;
    expiresIn?: number;
    expiresInMs?: number;
    /** 
    * Full domain name, including the protocol
    * @example https://example.com.
    */
    domain: string;
    maxCacheEntries?: number;
  },
  providers?: Array<ProviderConfig<ZodType> | JsonProviderSpec>;
   jwt: {
     jwt_secret_key: string ;
     access_tokens: {
      expiresIn?: number;
      expiresInMs?: number;
      algorithm?: jwt.Algorithm | undefined;
      audience?: string,
      issuer?: string,
      subject?: string,
      jwtid?:   string,
      maxCacheEntries?: number,
      payload?: object;
     }
     refresh_tokens: {
      /** 
       * When true, every attempt to get a new access token when expired, will verify, and invalidate the refresh token, 
       * and produce fresh access and refresh token.
       */
       rotateOnEveryAccessExpiry: boolean;
      /** 
       * Time in ms for the token to be considered valid.
       */
       refresh_ttl: number;
      /** 
       * Your domain
       * @example example.com.
       */
       domain: string;
      /** 
       * The maximum allowed active and valid refresh tokens (sessions) for a user.
       */
       MAX_SESSION_LIFE: number;
       maxAllowedSessionsPerUser: number;
       /** 
       * Bypass MFA for the specified period of time in ml,
       * if maxAllowedSessionsPerUser is exceeded for a certain user, and if a user.
       *
       */
       byPassAnomaliesFor: number;
     }
   },
  email: {
      resend_key: string;
      email: string;
    }
    rate_limiters?: {
        linkVerificationLimiter?: {
            unionLimiter: {
                burstLimiter: { 
                    inMemoryBlockOnConsumed: number,
                    points: number,
                    duration: number,
                    blockDuration: number,
                    inMemoryBlockDuration: number
                }
                slowLimiter: { 
                    inMemoryBlockOnConsumed: number,
                    points: number,
                    duration: number,
                    blockDuration: number,
                    inMemoryBlockDuration: number
                }
            }
        },
        loginLimiters?: {
             unionLimiter: {
                burstLimiter: { 
                    inMemoryBlockOnConsumed: number,
                    points: number,
                    duration: number,
                    blockDuration: number,
                    inMemoryBlockDuration: number
                }
                slowLimiter: { 
                    inMemoryBlockOnConsumed: number,
                    points: number,
                    duration: number,
                    blockDuration: number,
                    inMemoryBlockDuration: number
                }
            }, 
            ipLimiter: {
                    inMemoryBlockOnConsumed: number,
                    points: number,
                    duration: number,
                    blockDuration: number,
                    inMemoryBlockDuration: number
            },
            emailLimiter: {
                    inMemoryBlockOnConsumed: number,
                    points: number,
                    duration: number,
                    blockDuration: number,
                    inMemoryBlockDuration: number
            },
        },
        oauthLimiters?: {
           unionLimiter: {
                ipLimiterBrute: { 
                    inMemoryBlockOnConsumed: number,
                    points: number,
                    duration: number,
                    blockDuration: number,
                    inMemoryBlockDuration: number
                }
                ipLimiterSlow: { 
                    inMemoryBlockOnConsumed: number,
                    points: number,
                    duration: number,
                    blockDuration: number,
                    inMemoryBlockDuration: number
                }
            },
            subLimiter: {
                  inMemoryBlockOnConsumed: number,
                  points: number,
                  duration: number,
                  blockDuration: number,
                  inMemoryBlockDuration: number
            },
            compositeKeyLimiter: {
                  inMemoryBlockOnConsumed: number,
                  points: number,
                  duration: number,
                  blockDuration: number,
                  inMemoryBlockDuration: number
            }
        },

        signupLimiters: {
          unionLimiters: {
            uniLimiterIp: {
              ipLimit: {
                inMemoryBlockOnConsumed: number,
                points: number,
                duration: number,
                blockDuration: number,
                inMemoryBlockDuration: number
              },
              slowIpLimit: {
                inMemoryBlockOnConsumed: number,
                points: number,
                duration: number,
                blockDuration: number,
                inMemoryBlockDuration: number       
              }
            },
             uniLimiterComposite: {
                compositeKeyLimit: {
                inMemoryBlockOnConsumed: number,
                points: number,
                duration: number,
                blockDuration: number,
                inMemoryBlockDuration: number                  
                },
                slowCompositeKeyLimit: {
                  inMemoryBlockOnConsumed: number,
                  points: number,
                  duration: number,
                  blockDuration: number,
                  inMemoryBlockDuration: number                     
             }
          }
        },
        emailLimit: {
           inMemoryBlockOnConsumed: number,
           points: number,
           duration: number,
           blockDuration: number,
           inMemoryBlockDuration: number 
        }
    },
    tempPostRoutesLimiters?: {
      unionLimiters: {
        limit: {
           inMemoryBlockOnConsumed: number,
           points: number,
           duration: number,
           blockDuration: number,
           inMemoryBlockDuration: number           
        },
        slowLimit: {
           inMemoryBlockOnConsumed: number,
           points: number,
           duration: number,
           blockDuration: number,
           inMemoryBlockDuration: number 
        }
      },
      ipLimit: {
           inMemoryBlockOnConsumed: number,
           points: number,
           duration: number,
           blockDuration: number,
           inMemoryBlockDuration: number   
      }
    },
    tokenLimiters?: {
      unionLimiters: {
        refreshAccessTokenLimiter: { 
        accessTokenBrute: {
           inMemoryBlockOnConsumed: number,
           points: number,
           duration: number,
           blockDuration: number,
           inMemoryBlockDuration: number           
        },
        accessTokenSlow: {
           inMemoryBlockOnConsumed: number,
           points: number,
           duration: number,
           blockDuration: number,
           inMemoryBlockDuration: number 
        }
       },
        refreshTokenLimiterUnion: { 
        refreshTokenBrute: {
           inMemoryBlockOnConsumed: number,
           points: number,
           duration: number,
           blockDuration: number,
           inMemoryBlockDuration: number           
        },
        refreshTokenSlow: {
           inMemoryBlockOnConsumed: number,
           points: number,
           duration: number,
           blockDuration: number,
           inMemoryBlockDuration: number 
        }
       },

      },
      refreshTokenLimiter: {
           inMemoryBlockOnConsumed: number,
           points: number,
           duration: number,
           blockDuration: number,
           inMemoryBlockDuration: number         
      },
    },
    initPasswordResetLimiters?: {
      unionLimiters: { 
        limit: {
           inMemoryBlockOnConsumed: number,
           points: number,
           duration: number,
           blockDuration: number,
           inMemoryBlockDuration: number   
        },
        longLimiter: {
           inMemoryBlockOnConsumed: number,
           points: number,
           duration: number,
           blockDuration: number,
           inMemoryBlockDuration: number   
        }

      },
      ipLimiter: {
           inMemoryBlockOnConsumed: number,
           points: number,
           duration: number,
           blockDuration: number,
           inMemoryBlockDuration: number   
      },
      emailLimiter: {
           inMemoryBlockOnConsumed: number,
           points: number,
           duration: number,
           blockDuration: number,
           inMemoryBlockDuration: number   
      }

    }
  },
  logLevel?: 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal';
}
