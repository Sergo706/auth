# Copilot Instructions for JWT Auth Library

## Repository Overview

This is `@riavzon/jwtauth`, a comprehensive JWT authentication library for Node.js/Express applications. The library provides Express middleware, routes, and utilities for building authentication systems with features including user registration, login, OAuth flows, magic links, token rotation, MFA, and bot detection.

**Repository Stats:**
- **Language:** TypeScript (ES2020, Node.js modules)
- **Runtime:** Node.js 20+ 
- **Framework:** Express.js
- **Package Type:** ES Module library
- **Size:** Medium (200+ TypeScript files)
- **Dependencies:** 20+ core dependencies including Express, MySQL2, Zod, JWT, rate limiting, email, Telegram bot support

## Build & Development Commands

### Prerequisites & Environment Setup
- **Node.js:** v20.19.4+ required
- **npm:** v10.8.2+ required
- **Database:** MySQL (for user storage and rate limiting)

### Installation & Setup
**CRITICAL:** The repository has a git+ssh dependency that may cause npm install to hang in CI environments:

```bash
# Standard installation (may hang on git+ssh dependency)
npm install

# If npm install hangs (common issue), try:
npm install --omit=optional
# OR force timeout and continue
timeout 300 npm install || echo "Install may have timed out, check node_modules"
```

**Common Issue:** The `@riavzon/botdetector` dependency uses `git+ssh://git@github.com:Sergo706/botDetector.git#main` which requires SSH access and may hang in sandboxed environments. This is a known issue when working with the repository.

### Core Build Commands

**Always run commands in this order for successful builds:**

```bash
# 1. Install dependencies first (see installation notes above)
npm install

# 2. Build the TypeScript library
npm run build

# 3. Run tests
npm run test

# 4. Generate documentation
npm run docs:start
```

### Build Process Details

The `build` script does four critical steps:
```bash
npm run build
# Equivalent to:
# tsc -p tsconfig.json && 
# cp -R src/jwtAuth/emails dist/jwtAuth && 
# cp src/global.d.ts dist/global.d.ts && 
# cp src/jwtAuth/utils/disposable_email_blocklist.conf dist/jwtAuth/utils
```

**Key Points:**
- TypeScript compilation to `dist/`
- Email templates must be copied (EJS files)
- Global type definitions copied
- Email blocklist configuration file copied
- **Always copy assets after compilation** - the library will not work without email templates

### Testing
```bash
# Run test suite (uses Vitest)
npm run test

# Test files location: tests/
# Single test file: tests/jwts.test.ts
```

**Test Environment Notes:**
- Uses Vitest v3.2.4 as test runner (no explicit config file - uses defaults)
- Tests are minimal - mainly JWT token generation/verification 
- No database setup required for basic tests
- **Dependency Issue:** Tests may fail without `npm install` due to missing imports

### Documentation
```bash
# Generate TypeDoc + serve with VitePress
npm run docs:start

# Development mode
npm run docs:dev

# Build docs only
npm run docs:build

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
├── main.ts              # Main library exports
├── accessTokens.ts      # Access token generation/verification
├── refreshTokens.ts     # Refresh token rotation/management  
├── tempLinks.ts         # Temporary JWT links (MFA/password reset)
├── anomalies.ts         # Suspicious activity detection
└── jwtAuth/            # Core library implementation
    ├── config/         # Configuration & validation
    ├── controllers/    # Route handlers (login, OAuth, etc.)
    ├── middleware/     # Express middleware
    ├── models/         # Database helpers & schemas
    ├── routes/         # Express routers
    ├── types/          # TypeScript definitions
    ├── utils/          # Utilities (rate limiting, email, etc.)
    └── emails/         # EJS email templates
```

### Key Configuration Files
- **`tsconfig.json`:** TypeScript compilation (ES2020, NodeNext modules)
- **`package.json`:** Build scripts and dependencies
- **`typedoc.json`:** Documentation generation
- **`.vitepress/config.ts`:** Documentation site configuration

### Database Dependencies
The library requires two MySQL connection pools:
- **Main pool:** mysql2/promise for user operations
- **Rate limiter pool:** mysql2 callback API for rate limiting storage

Configuration schema: `src/jwtAuth/types/configSchema.ts`

### Critical Dependencies
- **Express:** Web framework and routing
- **Zod:** Schema validation (uses v4)
- **mysql2:** Database connectivity  
- **jsonwebtoken:** JWT operations
- **rate-limiter-flexible:** Rate limiting with MySQL backend
- **@riavzon/botdetector:** Bot detection (git+ssh dependency)
- **resend:** Email service integration
- **telegraf:** Telegram bot notifications

## Common Development Patterns

### Library Configuration
The library **must** be configured before use:
```typescript
import { configuration } from '@riavzon/jwtauth';

configuration({
  store: { main: promisePool, rate_limiters_pool: { store: callbackPool, dbName: 'auth' }},
  jwt: { secret: 'secret', expiresIn: '15m' },
  email: { /* SMTP/Resend config */ },
  // ... other required config
});
```

### Route Integration
```typescript
import { authenticationRoutes, magicLinks, tokenRotationRoutes } from '@riavzon/jwtauth';

app.use(authenticationRoutes);
app.use(magicLinks);
app.use('/token', tokenRotationRoutes);
```

### Middleware Usage
```typescript
import { requireAccessToken, protectRoute } from '@riavzon/jwtauth';

app.get('/protected', requireAccessToken, (req, res) => {
  // req.user contains validated token payload
});
```

## Validation & CI Considerations

### Pre-commit Validation
1. **TypeScript compilation:** `npm run build`
2. **Test suite:** `npm run test` 
3. **Documentation builds:** `npm run docs:build`

### GitHub Workflows
- **Dependabot:** Weekly dependency updates (`.github/dependabot.yml`)
- **No CI workflows present** - manual validation required

### Common Build Failures
1. **Missing email templates** - ensure `cp -R src/jwtAuth/emails dist/jwtAuth` runs after TypeScript compilation
2. **SSH dependency timeout** - `@riavzon/botdetector` dependency may hang npm install indefinitely in CI environments
3. **TypeScript compilation errors** - requires dependencies to be installed first (`npm install`)
4. **Missing configuration** - library throws runtime errors if `configuration()` not called
5. **Module resolution errors** - ensure ES2020+ target and NodeNext module resolution in tsconfig.json

**Build Time:** TypeScript compilation typically takes 30-60 seconds when dependencies are available.

## File Structure Reference

### Root Directory
```
/
├── .github/dependabot.yml    # Dependency management
├── .gitignore               # Build artifacts, logs, node_modules
├── README.md                # Usage documentation
├── package.json             # Dependencies and scripts
├── tsconfig.json           # TypeScript configuration
├── typedoc.json            # Documentation generation
├── .vitepress/config.ts    # Documentation site
├── src/                    # Source code
├── tests/                  # Test files
└── dist/                   # Compiled output (gitignored)
```

### Source Code Organization
**Controllers** (`src/jwtAuth/controllers/`): OAuth.ts, loginController.ts, signUpController.ts, etc.
**Routes** (`src/jwtAuth/routes/`): auth.ts, magicLinks.ts, TokenRotations.ts
**Middleware** (`src/jwtAuth/middleware/`): Authentication, validation, rate limiting
**Models** (`src/jwtAuth/models/`): Database operations and Zod schemas
**Types** (`src/jwtAuth/types/`): TypeScript definitions and configuration schema
**Utils** (`src/jwtAuth/utils/`): Rate limiting, email, logging, security utilities

### Key Files for Development
- **Main exports:** `src/main.ts`
- **Configuration schema:** `src/jwtAuth/types/configSchema.ts`
- **Database models:** `src/jwtAuth/models/`
- **Email templates:** `src/jwtAuth/emails/system.ejs`
- **Rate limiting:** `src/jwtAuth/utils/limiters/`

## Agent Instructions

**Trust these instructions** - they are comprehensive and tested. Only search for additional information if these instructions are incomplete or incorrect. The repository has specific quirks (SSH dependencies, email template copying, configuration requirements) that are documented here to save exploration time.

**When making changes:**
1. **Always run `npm run build`** after code modifications
2. **Test with `npm run test`** before committing
3. **Ensure email templates are present** in dist/ after build
4. **Be aware of the SSH dependency** when running npm install
5. **Configure the library properly** when testing functionality

**Quick Verification Workflow:**
```bash
# Verify repository state
npm install --omit=optional  # May timeout - this is expected
npx tsc --noEmit src/main.ts  # Check for basic TypeScript errors
npm run build                 # Full build (requires dependencies)
npm run test                  # Run test suite
ls dist/jwtAuth/emails/       # Verify email templates copied
```

**Expected Results:**
- npm install may hang on botdetector dependency
- TypeScript compilation will fail without dependencies
- Full build creates dist/ with all assets copied
- Single test file should pass if dependencies available