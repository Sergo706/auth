# Configuration Reference

This document provides comprehensive configuration options for the JWT Auth Library.

## Table of Contents

- [Overview](#overview)
- [Database Configuration](#database-configuration)
- [JWT Configuration](#jwt-configuration)
- [Email Configuration](#email-configuration)
- [Rate Limiting Configuration](#rate-limiting-configuration)
- [Security Configuration](#security-configuration)
- [Service Configuration](#service-configuration)
- [Environment Examples](#environment-examples)

## Overview

The JWT Auth Library requires comprehensive configuration via the `configuration()` function. All settings are validated using Zod schemas to ensure type safety and proper configuration.

```typescript
import { configuration } from '@riavzon/jwtauth';

configuration({
  store: { /* Database configuration */ },
  jwt: { /* JWT token settings */ },
  email: { /* Email service config */ },
  rate_limiters: { /* Rate limiting rules */ },
  // ... other sections
});
```

## Database Configuration

### Store Configuration

```typescript
{
  store: {
    main: Pool,                    // mysql2/promise Pool instance
    rate_limiters_pool: {
      store: Pool,                 // mysql2 Pool instance (callback API)
      dbName: string              // Database name for rate limiters
    }
  }
}
```

### Example Database Setup

```typescript
import mysql from 'mysql2';
import mysql2 from 'mysql2/promise';

const dbConfig = {
  host: 'localhost',
  port: 3306,
  user: 'auth_user',
  password: 'secure_password',
  database: 'jwt_auth_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

const mainPool = mysql2.createPool(dbConfig);
const rateLimiterPool = mysql.createPool(dbConfig);

configuration({
  store: {
    main: mainPool,
    rate_limiters_pool: {
      store: rateLimiterPool,
      dbName: 'jwt_auth_db'
    }
  }
  // ... other config
});
```

### Required Database Tables

The library requires specific database tables. Use the schema creation utility:

```bash
npm run build:createTables
```

Or manually create using the schema in `src/jwtAuth/models/schema.ts`.

## JWT Configuration

### Main JWT Settings

```typescript
{
  jwt: {
    jwt_secret_key: string,      // Main JWT signing secret
    access_tokens: {
      expiresIn?: string | number,       // Token lifetime (default: "15m")
      expiresInMs?: number,              // Lifetime in milliseconds
      algorithm?: string,                // Signing algorithm (default: "HS512")
      audience?: string,                 // Token audience
      issuer?: string,                   // Token issuer
      subject?: string,                  // Token subject
      jwtid?: string,                    // JWT ID
      maxCacheEntries?: number,          // Cache size (default: 5000)
      payload?: Record<string, unknown>  // Additional payload data
    },
    refresh_tokens: {
      rotateOnEveryAccessExpiry: boolean,     // Auto-rotate on access expiry
      refresh_ttl: number,                    // Refresh token TTL in ms
      domain: string,                         // Cookie domain
      MAX_SESSION_LIFE: number,               // Maximum session duration (ms)
      maxAllowedSessionsPerUser: number,      // Session limit per user
      byPassAnomaliesFor: number              // Anomaly bypass period (ms)
    }
  }
}
```

Notes:
- If `audience` or `issuer` are not provided, they default to `jwt.refresh_tokens.domain` for verification consistency across services.

### Example JWT Configuration

```typescript
{
  jwt: {
    jwt_secret_key: "your-256-bit-secret-key-here",
    access_tokens: {
      expiresIn: "15m",              // 15 minutes
      algorithm: "HS512",
      audience: "your-app-name",
      issuer: "auth.yourcompany.com",
      maxCacheEntries: 5000
    },
    refresh_tokens: {
      rotateOnEveryAccessExpiry: true,
      refresh_ttl: 7 * 24 * 60 * 60 * 1000,    // 7 days
      domain: "yourcompany.com",
      MAX_SESSION_LIFE: 30 * 24 * 60 * 60 * 1000,  // 30 days
      maxAllowedSessionsPerUser: 5,
      byPassAnomaliesFor: 24 * 60 * 60 * 1000      // 24 hours
    }
  }
}
```

### Security Recommendations

- **Secret Key**: Use a strong, randomly generated 256-bit secret
- **Access Token Lifetime**: Keep short (15-30 minutes) for security
- **Refresh Token Rotation**: Enable for enhanced security
- **Session Limits**: Reasonable limits prevent abuse (3-10 sessions)

## Email Configuration

### Basic Email Setup

```typescript
{
  email: {
    resend_key: string,    // Resend API key
    email: string          // From email address
  }
}
```

### Example Email Configuration

```typescript
{
  email: {
    resend_key: "re_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    email: "noreply@yourcompany.com"
  }
}
```

### Email Templates

The library includes built-in email templates for:
- Account verification
- Password reset
- MFA codes
- Security notifications

Templates are located in `src/jwtAuth/emails/` and use EJS templating.

## Rate Limiting Configuration

Rate limiting is highly configurable with multiple layers of protection.

### Rate Limiter Structure

```typescript
{
  inMemoryBlockOnConsumed: number,  // Requests before in-memory block
  points: number,                   // Request limit
  duration: number,                 // Time window (seconds)
  blockDuration: number,            // Block duration (seconds)
  inMemoryBlockDuration: number     // In-memory block duration (seconds)
}
```

### Login Rate Limiting

```typescript
{
  rate_limiters: {
    loginLimiters: {
      unionLimiter: {
        burstLimiter: {
          inMemoryBlockOnConsumed: 5,
          points: 5,              // 5 attempts
          duration: 60,           // in 1 minute
          blockDuration: 300,     // block for 5 minutes
          inMemoryBlockDuration: 300
        },
        slowLimiter: {
          inMemoryBlockOnConsumed: 15,
          points: 15,             // 15 attempts
          duration: 900,          // in 15 minutes
          blockDuration: 3600,    // block for 1 hour
          inMemoryBlockDuration: 3600
        }
      },
      ipLimiter: {
        inMemoryBlockOnConsumed: 10,
        points: 10,               // 10 attempts per IP
        duration: 600,            // in 10 minutes
        blockDuration: 1800,      // block for 30 minutes
        inMemoryBlockDuration: 1800
      },
      emailLimiter: {
        inMemoryBlockOnConsumed: 3,
        points: 3,                // 3 attempts per email
        duration: 3600,           // in 1 hour
        blockDuration: 7200,      // block for 2 hours
        inMemoryBlockDuration: 7200
      }
    }
  }
}
```

### Signup Rate Limiting

```typescript
{
  signupLimiters: {
    unionLimiters: {
      uniLimiterIp: {
        ipLimit: {
          inMemoryBlockOnConsumed: 3,
          points: 3,              // 3 signups per IP
          duration: 3600,         // in 1 hour
          blockDuration: 7200,    // block for 2 hours
          inMemoryBlockDuration: 7200
        },
        slowIpLimit: {
          inMemoryBlockOnConsumed: 10,
          points: 10,             // 10 signups per IP
          duration: 86400,        // in 24 hours
          blockDuration: 172800,  // block for 48 hours
          inMemoryBlockDuration: 172800
        }
      },
      uniLimiterComposite: {
        compositeKeyLimit: {
          inMemoryBlockOnConsumed: 2,
          points: 2,              // 2 signups per composite key
          duration: 1800,         // in 30 minutes
          blockDuration: 3600,    // block for 1 hour
          inMemoryBlockDuration: 3600
        },
        slowCompositeKeyLimit: {
          inMemoryBlockOnConsumed: 5,
          points: 5,              // 5 signups per composite key
          duration: 43200,        // in 12 hours
          blockDuration: 86400,   // block for 24 hours
          inMemoryBlockDuration: 86400
        }
      }
    },
    emailLimit: {
      inMemoryBlockOnConsumed: 1,
      points: 1,                  // 1 signup per email
      duration: 7200,             // in 2 hours
      blockDuration: 14400,       // block for 4 hours
      inMemoryBlockDuration: 14400
    }
  }
}
```

### Token Rotation Rate Limiting

```typescript
{
  tokenLimiters: {
    unionLimiters: {
      refreshAccessTokenLimiter: {
        accessTokenBrute: {
          inMemoryBlockOnConsumed: 10,
          points: 10,             // 10 refresh attempts
          duration: 300,          // in 5 minutes
          blockDuration: 600,     // block for 10 minutes
          inMemoryBlockDuration: 600
        },
        accessTokenSlow: {
          inMemoryBlockOnConsumed: 50,
          points: 50,             // 50 refresh attempts
          duration: 3600,         // in 1 hour
          blockDuration: 7200,    // block for 2 hours
          inMemoryBlockDuration: 7200
        }
      },
      refreshTokenLimiterUnion: {
        refreshTokenBrute: {
          inMemoryBlockOnConsumed: 5,
          points: 5,              // 5 session refresh attempts
          duration: 300,          // in 5 minutes
          blockDuration: 600,     // block for 10 minutes
          inMemoryBlockDuration: 600
        },
        refreshTokenSlow: {
          inMemoryBlockOnConsumed: 20,
          points: 20,             // 20 session refresh attempts
          duration: 3600,         // in 1 hour
          blockDuration: 7200,    // block for 2 hours
          inMemoryBlockDuration: 7200
        }
      }
    },
    refreshTokenLimiter: {
      inMemoryBlockOnConsumed: 3,
      points: 3,                  // 3 refresh token operations
      duration: 1800,             // in 30 minutes
      blockDuration: 3600,        // block for 1 hour
      inMemoryBlockDuration: 3600
    }
  }
}
```

## Security Configuration

### Password Security

```typescript
{
  password: {
    pepper: string,          // Password pepper (additional secret)
    hashLength?: number,     // Hash output length (default: 32)
    timeCost?: number,       // Argon2 time cost (default: 3)
    memoryCost?: number      // Argon2 memory cost (default: 65536)
  }
}
```

### Magic Links Configuration

```typescript
{
  magic_links: {
    jwt_secret_key: string,      // Secret for signing magic link JWTs
    expiresIn?: string | number, // Link expiry (default: "15m")
    expiresInMs?: number,        // Link expiry in milliseconds
    domain: string,              // Domain for link generation
    maxCacheEntries?: number     // Cache size (default: 1000)
  }
}
```

### Example Security Configuration

```typescript
{
  password: {
    pepper: "your-password-pepper-secret-key",
    hashLength: 32,
    timeCost: 3,
    memoryCost: 65536
  },
  magic_links: {
    jwt_secret_key: "your-magic-links-secret-key",
    expiresIn: "15m",
    domain: "https://yourapp.com",
    maxCacheEntries: 1000
  }
}
```

## Service Configuration

### Basic Service Settings

```typescript
{
  service?: {
    port?: number,              // Service port (default: 10000)
    ipAddress?: string,         // Bind address (default: "0.0.0.0")
    proxy?: {
      trust: boolean,           // Trust proxy headers
      ipToTrust: string,        // Trusted proxy IP
      server?: string           // Proxy server address
    },
    Hmac?: {
      sharedSecret: string,     // HMAC shared secret
      clientId: string,         // HMAC client ID
      maxClockSkew: number      // Maximum clock skew (seconds)
    }
  }
}
```

### Telegram Integration

```typescript
{
  telegram: {
    token: string,              // Telegram bot token
    allowedUser?: string,       // Allowed user ID
    chatID?: string            // Default chat ID for notifications
  }
}
```

### OAuth Providers

There are two ways to configure OAuth providers:

1) Library mode (code): pass actual Zod schemas in your app code.
2) Service mode (JSON): use a JSON-friendly DSL that the service converts to Zod at runtime.

Library mode (code)
```typescript
{
  providers?: Array<{
    name: string,               // Provider name (e.g., "google", "github")
    schema: ZodType             // Zod schema that validates `userInfo`
  }>
}
```

Service mode (JSON DSL)
- Each provider can be expressed as either:
  - `{ "name": "google", "useStandardProfile": true }` to use the built-in StandardProfileSchema, or
  - `{ "name": "github", "fields": { ... } }` to define a minimal schema using simple tokens.

- Allowed field tokens (add `?` to make optional):
  - `string`, `string?`
  - `email`, `email?`
  - `boolean`, `boolean?`
  - `url`, `url?`
  - `number`, `number?`
  - `int`, `int?`

JSON examples
```json
{
  "providers": [
    { "name": "google", "useStandardProfile": true },
    {
      "name": "github",
      "fields": {
        "sub": "string",
        "email": "email?",
        "given_name": "string?",
        "family_name": "string?",
        "avatar": "url?",
        "locale": "string?"
      }
    }
  ]
}
```

Runtime behavior
- The service reads `providers` from JSON and accepts them as-is.
- Internally, it builds a Zod schema from `fields` or uses the built-in StandardProfileSchema when `useStandardProfile` is true.
- The OAuth route expects `POST /auth/OAuth/:providerName` with a JSON body `{ "userInfo": { ... } }` matching the chosen schema.

### Example Service Configuration

```typescript
{
  service: {
    port: 10000,
    ipAddress: "0.0.0.0",
    proxy: {
      trust: true,
      ipToTrust: "10.0.0.1",
      server: "nginx-proxy"
    },
    Hmac: {
      sharedSecret: "your-hmac-shared-secret",
      clientId: "your-client-id",
      maxClockSkew: 300
    }
  },
  telegram: {
    token: "your-telegram-bot-token",
    chatID: "your-chat-id"
  },
  providers: [
    {
      name: "google",
      schema: z.object({
        client_id: z.string(),
        client_secret: z.string(),
        redirect_uri: z.string()
      })
    }
  ]
}
```

## Environment Examples

### Development Configuration

```typescript
{
  store: {
    main: createPool({
      host: 'localhost',
      user: 'dev_user',
      password: 'dev_password',
      database: 'jwt_auth_dev'
    }),
    rate_limiters_pool: {
      store: createPool({/* same config */}),
      dbName: 'jwt_auth_dev'
    }
  },
  jwt: {
    jwt_secret_key: "dev-secret-key-not-for-production",
    access_tokens: {
      expiresIn: "1h",           // Longer for development
      algorithm: "HS512"
    },
    refresh_tokens: {
      rotateOnEveryAccessExpiry: false,  // Disabled for easier debugging
      refresh_ttl: 24 * 60 * 60 * 1000, // 24 hours
      domain: "localhost",
      MAX_SESSION_LIFE: 7 * 24 * 60 * 60 * 1000,
      maxAllowedSessionsPerUser: 10,     // More sessions for testing
      byPassAnomaliesFor: 60 * 60 * 1000
    }
  },
  email: {
    resend_key: "test-key",
    email: "test@localhost"
  },
  rate_limiters: {
    // Relaxed rate limiting for development
    loginLimiters: {
      unionLimiter: {
        burstLimiter: {
          points: 100,           // Much higher limits
          duration: 60,
          blockDuration: 60
        }
      }
    }
  },
  logLevel: "debug"
}
```

### Production Configuration

```typescript
{
  store: {
    main: createPool({
      host: 'prod-db-host',
      user: 'prod_user',
      password: process.env.DB_PASSWORD,
      database: 'jwt_auth_prod',
      ssl: { rejectUnauthorized: false }
    }),
    rate_limiters_pool: {
      store: createPool({/* same config */}),
      dbName: 'jwt_auth_prod'
    }
  },
  jwt: {
    jwt_secret_key: process.env.JWT_SECRET,
    access_tokens: {
      expiresIn: "15m",          // Short for security
      algorithm: "HS512"
    },
    refresh_tokens: {
      rotateOnEveryAccessExpiry: true,   // Enhanced security
      refresh_ttl: 7 * 24 * 60 * 60 * 1000,
      domain: "yourcompany.com",
      MAX_SESSION_LIFE: 30 * 24 * 60 * 60 * 1000,
      maxAllowedSessionsPerUser: 3,      // Strict session limits
      byPassAnomaliesFor: 2 * 60 * 60 * 1000
    }
  },
  email: {
    resend_key: process.env.RESEND_API_KEY,
    email: "noreply@yourcompany.com"
  },
  rate_limiters: {
    // Strict rate limiting for production
    loginLimiters: {
      unionLimiter: {
        burstLimiter: {
          points: 5,             // Conservative limits
          duration: 60,
          blockDuration: 300
        },
        slowLimiter: {
          points: 15,
          duration: 900,
          blockDuration: 3600
        }
      }
    }
  },
  logLevel: "warn"
}
```

## Configuration Validation

The library uses Zod schemas for configuration validation:

```typescript
import { configurationSchema } from '@riavzon/jwtauth';

// Validate configuration before applying
const result = configurationSchema.safeParse(yourConfig);
if (!result.success) {
  console.error('Configuration validation failed:', result.error);
  process.exit(1);
}
```

## Environment Variables

For Docker deployment, sensitive values can be provided via environment variables:

```bash
# Database
DB_HOST=localhost
DB_PORT=3306
DB_USER=auth_user
DB_PASSWORD=secure_password
DB_NAME=jwt_auth_db

# JWT
JWT_SECRET=your-256-bit-secret-key
MAGIC_LINKS_SECRET=your-magic-links-secret

# Email
RESEND_API_KEY=re_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
FROM_EMAIL=noreply@yourcompany.com

# Telegram (optional)
TELEGRAM_BOT_TOKEN=your-telegram-bot-token
TELEGRAM_CHAT_ID=your-chat-id

# Security
PASSWORD_PEPPER=your-password-pepper-secret
HMAC_SHARED_SECRET=your-hmac-shared-secret
```

## Best Practices

### Security
1. **Use strong secrets** - Generate cryptographically random keys
2. **Rotate secrets regularly** - Implement secret rotation policies
3. **Environment separation** - Different secrets for dev/staging/prod
4. **Access control** - Limit who can access configuration files

### Performance
1. **Connection pooling** - Configure appropriate pool sizes
2. **Rate limiting** - Balance security and user experience
3. **Caching** - Use reasonable cache sizes for your traffic
4. **Monitoring** - Monitor configuration effectiveness

### Operational
1. **Configuration validation** - Always validate before deployment
2. **Backup configurations** - Version control your configurations
3. **Documentation** - Document any custom settings
4. **Testing** - Test configuration changes in staging first
