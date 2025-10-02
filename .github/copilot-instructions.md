# Copilot Instructions for JWT Auth Library

## Repository Overview

This is `@riavzon/jwtauth`, a comprehensive JWT authentication library for Node.js/Express applications. The library provides Express middleware, routes, and utilities for building authentication systems with features including user registration, login, OAuth flows, magic links, token rotation, MFA, and bot detection.

**Repository Stats:**
- **Language:** TypeScript (ES2020, Node.js ES modules)
- **Runtime:** Node.js 20+ 
- **Framework:** Express.js v5+
- **Package Type:** ES Module library
- **Size:** Medium (71+ TypeScript files across 8 directories)
- **Dependencies:** 20+ core dependencies including Express, MySQL2, Zod v4, JWT, rate limiting, email, Telegram bot support

## Build & Development Commands

### Prerequisites & Environment Setup
- **Node.js:** v20.19.5+ required
- **npm:** v10.8.2+ required  
- **Database:** MySQL 8.0+ (for user storage and rate limiting)

Environment tools available:
- **MySQL:** v8.0.43+ (client tools at `/usr/bin/mysql`)
- **nginx:** v1.24.0+ (available at `/usr/sbin/nginx`)
- **curl:** v8.5.0+ (available at `/usr/bin/curl`)
- **Node.js:** v20.19.5 and npm v10.8.2

**MySQL Access:** `mysql -h 127.0.0.1 -u root -p1234`

### Installation & Setup
**SSH Dependency Note:** Repository includes `@riavzon/botdetector` via git+ssh. In Copilot environment, this installs successfully without timeout.

```bash
# Standard installation
npm install
npm run build
```


### Core Build Commands

Recommended command order:

```bash
# 1. Install dependencies (includes SSH dependency)
npm install

# 2. Build TypeScript library
npm run build

# 3. Run tests (requires database setup)
npm run test

# 4. Generate documentation (4-5 seconds)
npm run docs:build

# 5. Run tests with coverage
npm run test:coverage
```

### Build Process Details

The `build` script executes five critical steps:
```bash
npm run build
# Executes: tsc -p tsconfig.json && [asset copying]
```

**Critical Asset Copying:**
1. Email templates: `src/jwtAuth/emails → dist/jwtAuth/emails`
2. Email blocklist: `src/jwtAuth/utils/disposable_email_blocklist.conf → dist/jwtAuth/utils/`
3. User agent data: `src/jwtAuth/models/useragent.csv → dist/jwtAuth/models/`


### Testing Setup

**Database Setup Required:**
```bash
# 1. Create test environment file
cat > .env << EOF
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=root
DB_PASS=1234
DB_NAME=app_db
EOF

# 2. Create database and basic schema
mysql -h 127.0.0.1 -u root -p1234 -e "CREATE DATABASE IF NOT EXISTS app_db;"
mysql -h 127.0.0.1 -u root -p1234 app_db << EOF
CREATE TABLE IF NOT EXISTS visitors (
    visitor_id INT AUTO_INCREMENT UNIQUE NOT NULL,
    canary_id VARCHAR(64) PRIMARY KEY,
    ip_address VARCHAR(45),
    user_agent TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT,
    visitor_id INT,
    FOREIGN KEY (visitor_id) REFERENCES visitors(visitor_id)
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
EOF

# 3. Run tests
npm run test
```

**Test Environment Notes:**
- Uses Vitest v3.2.4 with real database (no mocks allowed)
- Tests require `test/setup/` configuration (global hooks)
- Expected behavior: Some tests skip due to missing advanced configuration
- Test files organized in folders: `test/accessTokens-test/`, `test/refreshTokens-test/`

### Documentation
```bash
# Build documentation (VitePress + TypeDoc)
npm run docs:build        # ~4 seconds

# Development server
npm run docs:dev

# Start with TypeDoc generation  
npm run docs:start

# Preview built docs
npm run docs:preview
```

## Project Architecture & Layout

### Main Entry Point
- **Primary:** `src/main.ts` - exports all public APIs, routes, middleware
- **Compiled:** `dist/main.js` - final library entry point

### Core Modules (src/)
```
src/
├── main.ts              # Main library exports (~140 lines)
├── accessTokens.ts      # Access token generation/verification  
├── refreshTokens.ts     # Refresh token rotation/management
├── tempLinks.ts         # Temporary JWT links (MFA/password reset)
├── anomalies.ts         # Suspicious activity detection
├── service.ts           # Service entry point (Docker/standalone)
└── jwtAuth/            # Core library implementation
    ├── config/         # Configuration & validation
    ├── controllers/    # Route handlers (login, OAuth, etc.)
    ├── middleware/     # Express middleware
    ├── models/         # Database helpers & schemas (includes schema.ts)
    ├── routes/         # Express routers
    ├── types/          # TypeScript definitions
    ├── utils/          # Utilities (rate limiting, email, etc.)
    └── emails/         # EJS email templates (system.ejs)
```

### Key Configuration Files
- **`tsconfig.json`:** TypeScript ES2020, NodeNext modules, strict mode, incremental compilation
- **`tsconfig.prod.json`:** Production build configuration  
- **`package.json`:** ES module type, build scripts, 20+ dependencies
- **`vitest.config.ts`:** Test configuration with global setup
- **`typedoc.json`:** Documentation generation settings
- **`.vitepress/config.ts`:** Documentation site (VitePress v1.6+)
- **`test/setup/`:** Global test configuration and database setup

### Linting & Code Quality
- **No root-level linting tools** (no ESLint, Prettier configs)
- Quality enforced through TypeScript strict mode and manual review
- Uses TypeScript v10.9.2 for ts-node development

### Database Dependencies  
**Two MySQL connection pools required:**
- **Main pool:** mysql2/promise for user operations
- **Rate limiter pool:** mysql2 callback API for rate limiting storage

**Required Tables:** visitors, users, refresh_tokens (minimum for testing)
**Configuration schema:** `src/jwtAuth/types/configSchema.ts`

### Critical Dependencies
- **Express v5.1.0:** Web framework and routing
- **Zod v4.0.14:** Schema validation (note: v4, not v3)
- **mysql2 v3.14.0:** Database connectivity
- **jsonwebtoken v9.0.2:** JWT operations  
- **rate-limiter-flexible v7.0.0:** Rate limiting with MySQL backend
- **@riavzon/botdetector:** Bot detection (git+ssh dependency from Sergo706/botDetector)
- **resend v6.0.1:** Email service integration
- **telegraf v4.16.3:** Telegram bot notifications
- **argon2 v0.44.0:** Password hashing
- **pino v9.7.0:** Structured logging

## Common Development Patterns

### Library Configuration
The library **must** be configured before use:
```typescript
import { configuration } from '@riavzon/jwtauth';

configuration({
  store: { main: promisePool, rate_limiters_pool: { store: callbackPool, dbName: 'auth' }},
  jwt: { jwt_secret_key: 'secret', access_tokens: { expiresIn: '15m' } },
  email: { resend_key: 'key', email: 'sender@domain.com' },
  password: { pepper: 'secret-pepper' },
  magic_links: { jwt_secret_key: 'magic-secret', domain: 'https://domain.com' },
  telegram: { token: 'telegram-bot-token' },
  logLevel: 'info'
});
```

### Route Integration
```typescript
import { authenticationRoutes, magicLinks, tokenRotationRoutes } from '@riavzon/jwtauth';

app.use(authenticationRoutes);        // /signup, /login, /auth/oauth/:provider
app.use(magicLinks);                  // /auth/verify-mfa/:visitor, /auth/forgot-password  
app.use('/token', tokenRotationRoutes); // /token/rotate
```

### Middleware Usage
```typescript
import { requireAccessToken, protectRoute } from '@riavzon/jwtauth';

app.get('/protected', requireAccessToken, (req, res) => {
  // req.user contains validated token payload
});
```

## Validation & CI Considerations

### Pre-commit Validation Sequence
1. **Clean build:** `rm -rf dist && npm run build` (3-5 seconds)
2. **Test suite:** `npm run test` (requires database setup)
3. **Documentation:** `npm run docs:build` (4-5 seconds)

### GitHub Workflows
- **Dependabot:** Weekly dependency updates (`.github/dependabot.yml`)
- **Copilot Setup:** GitHub Actions workflow (`.github/workflows/copilot-setup-steps.yml`):
  - MySQL 8.4 database service on port 3306
  - SSH agent setup for botdetector dependency (`BOTDETECTOR_DEPLOY_KEY` secret)
  - Node.js 20 with npm caching
  - Complete build and test pipeline validation

### Common Build Failures & Solutions

**1. "No such file or directory" during asset copying:**
```bash
# Problem: dist/jwtAuth doesn't exist when cp commands run
# Solution: Ensure TypeScript compilation completes first, or:
mkdir -p dist/jwtAuth && npm run build
```

**2. SSH dependency timeout:**
```bash
# Problem: @riavzon/botdetector git+ssh dependency hangs
# Solution: In Copilot environment, this works reliably
# For other environments, ensure SSH agent is configured
```

**3. Missing configuration error:**
```bash
# Problem: Tests fail with "Must be called once" configuration error
# Solution: This is expected - library requires configuration before use
```

**4. Database connection errors:**
```bash
# Problem: Tests fail with MySQL connection errors
# Solution: Set environment variables and create database schema (see Testing Setup)
```

**Build Troubleshooting Commands:**
```bash
# Complete clean build
rm -rf dist/ node_modules/ package-lock.json
npm install
npm run build

# Clear TypeScript cache
rm -f tsconfig.tsbuildinfo
npm run build

# Verify asset copying
ls -la dist/jwtAuth/emails/system.ejs
ls -la dist/jwtAuth/utils/disposable_email_blocklist.conf  
ls -la dist/jwtAuth/models/useragent.csv
```

## File Structure Reference

### Root Directory Files
```
/
├── .github/
│   ├── dependabot.yml              # Weekly dependency updates
│   ├── workflows/
│   │   └── copilot-setup-steps.yml # MySQL + SSH setup for CI/CD
│   └── copilot-instructions.md     # This file
├── .vitepress/config.ts            # Documentation site configuration
├── .dockerignore                   # Docker build exclusions
├── .gitignore                     # Git exclusions (logs, dist/, node_modules)
├── .npmignore                     # Package publication exclusions
├── Dockerfile                     # Production containerization
├── README.md                      # Usage documentation and examples
├── package.json                   # Dependencies, scripts, ES module config
├── package-lock.json              # Dependency lockfile  
├── tsconfig.json                  # Development TypeScript config
├── tsconfig.prod.json             # Production TypeScript config
├── typedoc.json                   # API documentation generation
├── vitest.config.ts               # Test configuration
├── docker-compose.yml             # Local development services
├── start.sh                       # Development startup script
├── decrypt.sh                     # Production config decryption
├── *.png                          # Flow diagrams (minimal-flow, mfa-minimal-flow, multi)
├── src/                           # TypeScript source code
├── test/                          # Test suites and setup
├── dist/                          # Compiled output (gitignored)
└── docs/                          # Generated documentation (gitignored)
```

### Source Code Organization
```
src/jwtAuth/
├── config/                        # Configuration management
│   └── configuration.ts           # Main configuration schema & validation
├── controllers/                   # HTTP route handlers
│   ├── loginController.ts         # Login endpoint logic
│   ├── signUpController.ts        # Registration endpoint logic
│   └── OAuth.ts                   # OAuth provider integration
├── middleware/                    # Express middleware
│   ├── requireAccessToken.js      # JWT verification middleware
│   ├── fingerPrint.js             # Device fingerprinting
│   └── validateContentType.js     # Request validation
├── models/                        # Database operations
│   ├── schema.ts                  # Database table definitions
│   ├── createUser.js              # User creation helpers
│   └── useragent.csv              # User agent patterns (asset file)
├── routes/                        # Express routers  
│   ├── auth.ts                    # Authentication routes (/signup, /login)
│   ├── magicLinks.ts              # Magic link routes (/auth/verify-mfa, /auth/forgot-password)
│   └── TokenRotations.ts          # Token rotation routes (/token/rotate)
├── types/                         # TypeScript definitions
│   └── configSchema.ts            # Configuration type definitions
├── utils/                         # Utility functions
│   ├── limiters/                  # Rate limiting configurations
│   ├── hash.js                    # Password hashing (argon2)
│   ├── logger.ts                  # Structured logging (pino)
│   ├── emailTemplateMaker.js      # Email template management
│   └── disposable_email_blocklist.conf # Email validation data (asset file)
└── emails/                        # Email templates
    └── system.ejs                 # System email template (asset file)
```

### Test Structure
```
test/
├── setup/                         # Global test configuration
│   ├── test.setup.ts              # Vitest global hooks  
│   ├── testConfig.ts              # Database pool configuration
│   └── setupTestDB.ts             # Database initialization
├── accessTokens-test/             # Access token functionality tests
│   └── jwt-verification.test.ts   # JWT verification edge cases
└── refreshTokens-test/            # Refresh token functionality tests
```

## Agent Instructions

**Trust these instructions** - they are comprehensive and tested through hands-on validation. Only search for additional information if these instructions are incomplete or incorrect. The repository has specific quirks (SSH dependencies, asset file copying, configuration requirements) that are documented here to save exploration time.

**When making changes:**
1. **Always run `npm run build`** after code modifications  
2. **Test with environment setup:** Create `.env` file and database schema before running tests
3. **Verify asset files copied:** Check `dist/jwtAuth/emails/`, `dist/jwtAuth/utils/`, `dist/jwtAuth/models/` 
4. **Handle SSH dependency properly:** In Copilot environment, `npm install` works reliably
5. **Configure library before testing:** All runtime features require `configuration()` call

**Critical Asset Files Verification:**
After building, these files MUST exist:
- `dist/jwtAuth/emails/system.ejs` (6KB+ EJS email template)
- `dist/jwtAuth/models/useragent.csv` (466KB+ user agent patterns) 
- `dist/jwtAuth/utils/disposable_email_blocklist.conf` (57KB+ email domain blocklist)
- `dist/global.d.ts` (global type definitions)

**Quick Development Workflow:**
```bash
# 1. Verify environment
npm install                        # SSH dependency works in Copilot
npm run build                      # 3-5 seconds, creates dist/ with assets

# 2. Setup testing (first time only)
cat > .env << 'EOF'
DB_HOST=127.0.0.1
DB_PORT=3306  
DB_USER=root
DB_PASS=1234
DB_NAME=app_db
EOF

mysql -h 127.0.0.1 -u root -p1234 -e "CREATE DATABASE IF NOT EXISTS app_db;"
# [Create basic schema - see Testing Setup section]

# 3. Validate
npm run test                       # Some tests may skip - expected behavior
npm run docs:build                 # 4-5 seconds
ls dist/jwtAuth/emails/            # Verify assets copied correctly
```

**Expected Results:**
- Build completes in 3-5 seconds consistently
- Test suite runs with some expected configuration-related skips
- Documentation generates successfully  
- All asset files properly copied to dist/
