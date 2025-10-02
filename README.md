# JWT Auth Library (@riavzon/jwtauth)

A comprehensive JWT authentication library for Node.js/Express applications providing enterprise-grade security features including user authentication, OAuth integration, multi-factor authentication, magic links, token rotation, rate limiting, and bot detection.

##  Quick Start

```bash
npm install @riavzon/jwtauth
```

```typescript
import express from 'express';
import { configuration, authenticationRoutes, magicLinks, tokenRotationRoutes } from '@riavzon/jwtauth';

const app = express();

// Configure the library
configuration({
  store: { /* database pools */ },
  jwt: { /* JWT secrets and options */ },
  email: { /* email service config */ },
  // ... other config
});

// Mount authentication routes
app.use(authenticationRoutes);      // /signup, /login, /auth/OAuth/:providerName
app.use(magicLinks);               // MFA and password reset flows  
app.use('/token', tokenRotationRoutes); // Token rotation and logout

app.listen(3000);
```

##  Features

- **Complete Authentication System**: Sign up, login, logout with secure password handling
- **Token Management**: JWT access/refresh token rotation and revocation
- **OAuth Integration**: Support for third-party OAuth providers
- **Magic Links**: Passwordless authentication and account recovery
- **Multi-Factor Authentication**: Email-based MFA with temporary links
- **Rate Limiting**: Advanced rate limiting with MySQL backend storage
- **Bot Detection**: Integrated bot detection and suspicious activity monitoring
- **Analytics**: Visitor tracking, geolocation, and user-agent analysis
- **Security Headers**: Helmet integration with secure defaults
- **Cross-Platform**: Works with web, mobile, and API clients

## Library vs Service

- Library usage: Import the library into your Express application and mount the provided routers and middleware. You control routing prefixes, CSRF, and application-specific concerns.
- Service usage: Run the included standalone service (via Docker or Node). It uses secure defaults and is configured via JSON. The service exposes the same REST endpoints but does not include CSRF or a full OAuth browser flow.
- Client library: For production frontends, use a client integration to add CSRF protection and end-to-end OAuth flows. CSRF and full OAuth browser-based flows are intentionally not part of this service.

##  Project Structure

```
src/
├── main.ts                    # Main library exports and public API
├── service.ts                 # Standalone service entry point
├── accessTokens.ts           # Access token generation and verification
├── refreshTokens.ts          # Refresh token issuance and rotation
├── tempLinks.ts              # Temporary JWT links (MFA & password reset)
├── anomalies.ts              # Heuristics for detecting suspicious activity
└── jwtAuth/
    ├── config/               # Library configuration and validation
    ├── controllers/          # Route handlers (login, logout, OAuth, etc.)
    ├── middleware/           # Express middleware for auth and security
    ├── models/               # Database helpers and user management
    ├── routes/               # Express routers bundled with the library
    ├── types/                # TypeScript type definitions
    ├── utils/                # Utilities (rate limiters, email, hashing, etc.)
    └── emails/               # EJS email templates
```

##  Installation & Setup

### Library Usage

Install the library in your existing Express application:

```bash
npm install @riavzon/jwtauth
```

### Service Deployment

For standalone deployment, use the provided Docker configuration:

```bash
# 1. Configure your service
# Start from the provided example and edit it:
cp config.dev.json config.json
# Adjust values for your environment

# 2. Validate configuration
npm run validate-config     # Check configuration before deployment

# 3. Deploy with Docker
./start.sh
```

The service will be available at `http://localhost:10000` with the following health endpoint:
- `GET /health` - Service health check

##  Configuration

The library requires comprehensive configuration before use. Call `configuration()` once at startup:

```typescript
import { configuration } from '@riavzon/jwtauth';

configuration({
  // Database connections
  store: {
    main: promisePool,                    // mysql2/promise Pool
    rate_limiters_pool: {
      store: callbackPool,                // mysql2 Pool  
      dbName: 'your_database'
    }
  },
  
  // JWT settings
  jwt: {
    jwt_secret_key: 'your-secret-key',
    access_tokens: {
      expiresIn: '15m',
      algorithm: 'HS512'
    },
    refresh_tokens: {
      rotateOnEveryAccessExpiry: true,
      refresh_ttl: 7 * 24 * 60 * 60 * 1000,  // 7 days
      domain: 'yourdomain.com',
      maxAllowedSessionsPerUser: 5
    }
  },
  
  // Email service (Resend)
  email: {
    resend_key: 'your-resend-api-key',
    email: 'noreply@yourdomain.com'
  },
  
  // Password security
  password: {
    pepper: 'your-pepper-secret'
  },
  
  // Magic links for MFA/password reset
  magic_links: {
    jwt_secret_key: 'your-magic-links-secret',
    domain: 'https://yourdomain.com',
    expiresIn: '15m'
  },
  
  // Telegram notifications (optional)
  telegram: {
    token: 'your-bot-token',
    chatID: 'your-chat-id'
  },
  
  // Rate limiting configuration
  rate_limiters: {
    // Comprehensive rate limiting settings
    // See CONFIGURATION.md for details
  }
});
```

For complete configuration options, see [`CONFIGURATION.md`](./CONFIGURATION.md).

## API Routes

### Authentication Routes (`authenticationRoutes`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/signup` | Create a new user account |
| `POST` | `/login` | Authenticate user and get tokens |
| `POST` | `/auth/OAuth/:providerName` | OAuth authentication (provider-defined `userInfo` payload) |

### Magic Links (`magicLinks`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/auth/verify-mfa/:visitor` | Validate MFA link (confirmation only) |
| `POST` | `/auth/verify-mfa/:visitor` | Verify MFA code (issues new tokens) |
| `POST` | `/auth/forgot-password` | Initiate password reset flow |
| `GET`  | `/auth/reset-password/:visitor` | Validate password reset link (confirmation only) |
| `POST` | `/auth/reset-password/:visitor` | Complete password reset |

### Token Management (`tokenRotationRoutes`)

Default routes are defined under `/auth/*` when mounted without a prefix:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/refresh-access` | Rotate access token |
| `POST` | `/auth/user/refresh-session` | Rotate and issue new refresh tokens |
| `POST` | `/auth/logout` | Revoke current refresh token |
| `POST` | `/auth/refresh-session/rotate-every` | Rotate both access and refresh tokens |

If you mount the router under a prefix (e.g., `app.use('/token', tokenRotationRoutes)`), the final routes become `/token/auth/*`.

### Middleware

```typescript
import { protectRoute, requireAccessToken, requireRefreshToken } from '@riavzon/jwtauth';

// Protect routes requiring authentication
app.get('/protected', requireAccessToken, protectRoute, (req, res) => {
  // req.user contains validated token payload
  res.json({ user: req.user });
});

// Routes requiring both access and refresh tokens
app.post('/sensitive-action', 
  requireAccessToken, 
  requireRefreshToken, 
  protectRoute, 
  (req, res) => {
    // High-security action
  }
);
```

##  Architecture Patterns

### Centralized Authentication Service

This library is designed for centralized authentication architecture:

```

### BFF Access Route

The library includes a minimal BFF authorization endpoint:

- `GET /secret/data` (via `bffAccessRoute`) — protected by `requireAccessToken`, `requireRefreshToken`, and `protectRoute`. Returns `{ authorized: boolean, roles, ipAddress, userAgent, date }`.

Mount with:

```typescript
import { bffAccessRoute, requireAccessToken, requireRefreshToken, protectRoute } from '@riavzon/jwtauth';

app.use(bffAccessRoute);
// Internally, the route wires the required middleware before the controller
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Client    │    │     BFF     │    │  Database   │
│ (Frontend)  │◄──►│   Server    │    │   Server    │
└─────────────┘    └─────────────┘    └─────────────┘
                           │                   ▲
                           ▼                   │
                   ┌─────────────┐             │
                   │  Auth API   │─────────────┘
                   │   Service   │
                   └─────────────┘
```

1. **Client/Frontend** submits credentials to BFF server
2. **BFF Server** forwards authentication requests to Auth API Service  
3. **Auth API Service** validates credentials and issues JWT tokens
4. **Database** stores user data and session information (accessed only by Auth Service)
5. **Tokens** are used for subsequent API calls across services

### Multi-Instance Deployment

Multiple Auth API instances can share the same configuration:

- Point all instances to the same MySQL database
- Token verification and rate limiting stay consistent
- Horizontal scaling without session affinity issues

## Security Features

### Token Security
- **Access Tokens**: Short-lived (15min default), stateless JWT verification
- **Refresh Tokens**: Long-lived, stored hashed in database with rotation
- **Token Rotation**: Automatic rotation on access token expiry (configurable)
- **Session Management**: Multiple sessions per user with configurable limits

### Rate Limiting
- **Multi-layer Protection**: IP, email, and composite key rate limiting
- **MySQL Backend**: Persistent rate limiting across service restarts
- **Configurable Thresholds**: Burst and sustained rate limiting
- **Automatic Blocking**: Temporary blocks for suspicious activity

### Bot Detection
- **User Agent Analysis**: Pattern matching against known bot signatures  
- **Geolocation Tracking**: Country/region-based access controls
- **Behavioral Analysis**: Request pattern anomaly detection
- **Integration**: Built-in with `@riavzon/botdetector` library

### Security Headers
- **Helmet Integration**: Security headers with safe defaults
- **XSS Protection**: Input sanitization and output encoding helpers
- **Content Security Policy**: Add CSP directives suitable for your application
- **CSRF**: Not included by default in the service; add CSRF in your client or gateway

## Docker Deployment

### Quick Start

1. **Configure your service:**
   ```bash
   # Start from the provided example and edit it
   cp config.dev.json config.json
   ```

2. **Deploy with Docker:**
   ```bash
   chmod +x start.sh
   ./start.sh
   ```

3. **Verify deployment:**
   ```bash
   curl http://localhost:10000/health
   # Should return: OK
   ```

### Docker Components

- **`Dockerfile`**: Multi-stage build with security hardening
- **`docker-compose.yml`**: Service orchestration with security policies  
- **`start.sh`**: Automated deployment script with secret management
- **`config.json`**: Service configuration (see example provided)

### Production Configuration

The Docker setup includes:
- **Security**: Read-only filesystem, dropped capabilities, non-root user
- **Secret Management**: Age encryption for configuration files
- **Logging**: Persistent log volumes for debugging
- **Health Checks**: Built-in service health monitoring
- **Resource Limits**: PID and memory limits for container security

##  Development

### Prerequisites
- Node.js 20+ 
- MySQL 8+
- npm 10+

### Setup
```bash
git clone <repository>
cd auth
npm install
npm run build
```

### Testing
```bash
# Configure test database
export DB_HOST=localhost
export DB_PORT=3306  
export DB_USER=root
export DB_PASS=password
export DB_NAME=jwtauth_test

# Run tests
npm test
```

### Building
```bash
npm run build              # Build library
npm run build:prod         # Production build
npm run build:createTables # Create database tables
npm run validate-config    # Validate configuration
```

### Documentation
```bash
npm run docs:dev           # Development server
npm run docs:build         # Build static docs
npm run docs:start         # Generate and serve docs
```

## Additional Documentation

- **[ARCHITECTURE.md](./ARCHITECTURE.md)** - System design and deployment patterns
- **[CONFIGURATION.md](./CONFIGURATION.md)** - Complete configuration reference  
- **[API.md](./API.md)** - Detailed API endpoint documentation
- **[DEPLOYMENT.md](./DEPLOYMENT.md)** - Production deployment guide
- **[DEVELOPMENT.md](./DEVELOPMENT.md)** - Development and contribution guide
 - **[SERVICE.md](./SERVICE.md)** - Using this repo as a service vs a library

## Integration Examples

### Basic Express Integration
```typescript
import express from 'express';
import mysql from 'mysql2/promise';
import { configuration, authenticationRoutes } from '@riavzon/jwtauth';

const app = express();
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root', 
  password: 'password',
  database: 'myapp'
});

configuration({
  store: { 
    main: pool,
    rate_limiters_pool: { store: mysql.createPool(config), dbName: 'myapp' }
  },
  jwt: { jwt_secret_key: 'your-secret' },
  // ... other config
});

app.use(express.json());
app.use(authenticationRoutes);

app.listen(3000);
```

### Protected Route Example
```typescript
import { protectRoute, requireAccessToken } from '@riavzon/jwtauth';

app.get('/api/profile', 
  requireAccessToken,
  protectRoute, 
  async (req, res) => {
    const { userId } = req.user;
    // Fetch user profile using userId
    res.json({ profile: userProfile });
  }
);
```

### OAuth Integration
```typescript
import { configureOauthProviders } from '@riavzon/jwtauth';

configureOauthProviders([
  {
    name: 'google',
    schema: z.object({
      client_id: z.string(),
      client_secret: z.string(),
      redirect_uri: z.string()
    })
  }
]);

// OAuth routes automatically available at (case-insensitive unless configured otherwise):
// POST /auth/OAuth/google
```

For detailed development setup, see [DEVELOPMENT.md](./DEVELOPMENT.md).

---

**Note**: This library requires MySQL for user storage and rate limiting. Ensure your database is properly configured before deployment.
