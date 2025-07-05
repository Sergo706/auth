import jwt from 'jsonwebtoken'
import { ProviderConfig, StandardProfile } from '../utils/newOauthProvider.js';
import { ZodType } from 'zod/v4';

export interface AuthConfig {
  store: {
    host:     string;
    port:     number;
    user:     string;
    password: string;
    databaseName:     string;
    waitForConnection : boolean;
    connectionLimit: number;
    queueLimit: number;
    connectTimeout: number;  
  };
  telegram: {
    token:        string;
    allowedUser?: string;
    chatID?:      string;
  };
  password: {
      pepper: string;
      hashLength: number;
      timeCost: number;
      memoryCost: number;
    },
 
  magic_links: {
    jwt_secret_key: string;
    expiresIn: number;
    domain: string;
  },
  providers?: ProviderConfig<ZodType>[];
   jwt: {
     jwt_secret_key: string ;
     access_tokens: {
      expiresIn: number;
      algorithm: jwt.Algorithm | undefined;
      audience?: string,
      issuer?: string,
      subject?: string,
      jwtid?:   string,
     }
     refresh_tokens: {
       rotateOnEveryAccessExpiry: boolean;
       refresh_ttl: number;
       domain: string;
       magicLinks: string;
       MAX_SESSION_LIFE: number;
     }
   },
  email: {
      resend_key: string;
      email: string;
    },

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
