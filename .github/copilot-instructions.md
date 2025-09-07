# Copilot Instructions for JWT Auth Library

## Repository Overview

This is `@riavzon/jwtauth`, a comprehensive JWT authentication library for Node.js/Express applications. The library provides Express middleware, routes, and utilities for building authentication systems with features including user registration, login, OAuth flows, magic links, token rotation, MFA, and bot detection.

**Repository Stats:**
- **Language:** TypeScript (ES2020, Node.js modules)
- **Runtime:** Node.js 20+ 
- **Framework:** Express.js
- **Package Type:** ES Module library
- **Size:** Medium (71 TypeScript files)
- **Dependencies:** 20+ core dependencies including Express, MySQL2, Zod, JWT, rate limiting, email, Telegram bot support

## Build & Development Commands

### Prerequisites & Environment Setup
- **Node.js:** v20.19.4+ required
- **npm:** v10.8.2+ required
- **Database:** MySQL (for user storage and rate limiting)

**✅ Copilot Environment Confirmed:** The following tools are pre-installed and available in the Copilot coding environment:
- **MySQL:** v8.0.43+ (MySQL client tools available via `/usr/bin/mysql`)
- **nginx:** v1.24.0+ (Available via `/usr/sbin/nginx`)
- **curl:** v8.5.0+ (Available via `/usr/bin/curl`)
- **Node.js:** v20.19.4 and npm v10.8.2 (meets all requirements)

These tools are ready to use without additional installation steps.
Password for your mysql is 1234 user is root.
if for some reason you cant access the mysql instance check its configurations and configure it.
### Installation & Setup
**ENVIRONMENT-DEPENDENT:** The repository has a git+ssh dependency:

```bash
# Standard installation (usually works)
npm install
```


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
# 5. Generate tests with coverage
npm run test:coverage
```

### Build Process Details

The `build` script does five critical steps:
```bash
npm run build
# Equivalent to:
# tsc -p tsconfig.json && 
# cp -R src/jwtAuth/emails dist/jwtAuth && 
# cp src/global.d.ts dist/global.d.ts && 
# cp src/jwtAuth/utils/disposable_email_blocklist.conf dist/jwtAuth/utils &&
# cp src/jwtAuth/models/useragent.csv dist/jwtAuth/models
```

**Key Points:**
- TypeScript compilation to `dist/`
- Email templates must be copied (EJS files)
- Global type definitions copied
- Email blocklist configuration file copied
- User agent CSV data file copied
- **Always copy assets after compilation** - the library will not work without email templates and data files

### Testing
```bash
# Run test suite (uses Vitest)
npm run test

# Test files location: tests/
# Single test file: tests/jwts.test.ts
```

**Test Environment Notes:**
- Uses Vitest v3.2.4 as test runner (Use the default configurations changes the your env to suite the your mysql for tests)

- Tests should be breaked into folders a minimal files check the structure for an example
- Test should be configured globally check the structure for an example
- Test needs to be configured with database
- Mocks are not allowed to be used, use real implementations when writing tests.
- **Configuration Required:** Tests fail without library configuration (expected behavior - not a bug)
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
- **`tsconfig.json`:** TypeScript compilation (ES2020, NodeNext modules, incremental compilation enabled)
- **`package.json`:** Build scripts and dependencies
- **`typedoc.json`:** Documentation generation
- **`.vitepress/config.ts`:** Documentation site configuration
- **`.vitest.config.ts`:** Test configuration
- **`test/setup/*`:** Test configuration functions hooks and helpers.


### Linting & Code Quality
- **No root-level linting configuration** - no ESLint, Prettier, or other linting tools configured at project level
- Code quality is managed through TypeScript strict mode and manual review

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
- **Copilot Setup:** GitHub Actions workflow (`.github/copilot-setup-steps.yml`) with:
  - MySQL 8.4 database service setup
  - SSH key handling for botdetector dependency (`BOTDETECTOR_DEPLOY_KEY` secret required)
  - Node.js 20 setup with npm caching
  - Complete build and test pipeline
- **Manual validation required** for most changes

### Common Build Failures
1. **Missing assets after compilation** - ensure all asset copying runs after TypeScript compilation:
   - `cp -R src/jwtAuth/emails dist/jwtAuth` (email templates)
   - `cp src/global.d.ts dist/global.d.ts` (type definitions)
   - `cp src/jwtAuth/utils/disposable_email_blocklist.conf dist/jwtAuth/utils` (email blocklist)
   - `cp src/jwtAuth/models/useragent.csv dist/jwtAuth/models` (user agent data)
2. **SSH dependency timeout** - `@riavzon/botdetector` dependency may hang npm install indefinitely in CI environments
3. **TypeScript compilation errors** - requires dependencies to be installed first (`npm install`)
4. **Missing configuration** - library throws runtime errors if `configuration()` not called
5. **Module resolution errors** - ensure ES2020+ target and NodeNext module resolution in tsconfig.json

**Build Time:** TypeScript compilation typically takes 2-5 seconds when dependencies are available.

**✅ Validated Working:** All components confirmed working in Copilot environment:
- npm install completes successfully (botDetector SSH dependency resolves correctly)
- Full build process completes in ~4 seconds with all assets copied
- ES module imports work correctly (main library and botDetector exports)
- Test suite runs as expected (configuration errors are expected behavior)
- Documentation builds successfully with VitePress
- MySQL, nginx, and curl tools are available and functional

**Build Troubleshooting:** If builds fail with copy errors after TypeScript compilation, try:
```bash
# Clear TypeScript incremental build cache
rm -f tsconfig.tsbuildinfo
npm run build

# If npm install fails due to prepare script, create dist directory first
mkdir -p dist/jwtAuth
npm install

# For complete clean build (recommended for troubleshooting)
rm -rf dist/ && rm -f tsconfig.tsbuildinfo && npm run build
```

**Important:** The package.json includes a `prepare` script that runs the build during `npm install`. If dist/ doesn't exist, npm install will fail.

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
- **Asset files:** `src/jwtAuth/utils/disposable_email_blocklist.conf`, `src/jwtAuth/models/useragent.csv`

## CI/CD & Environment Setup

### GitHub Actions Workflow
The repository includes a comprehensive setup workflow (`.github/copilot-setup-steps.yml`) that:

**Services:**
- **MySQL 8.4:** Database service on port 3306 with health checks
- **Nginx 1.27:** Web server on port 8080 for testing

**Setup Steps:**
1. **Node.js 20 environment** with npm cache
2. **SSH agent setup** for botdetector dependency (requires `BOTDETECTOR_DEPLOY_KEY` secret)
3. **MySQL client tools** installation
4. **Database health check** with 60-second timeout
5. **Dependencies installation** (`npm install`)
6. **Build process** (`npm run build`)

**Required Secrets:**
- `BOTDETECTOR_DEPLOY_KEY`: SSH private key for accessing the botdetector repository

### Local Development Environment
For local development without CI setup:
```bash
# Standard installation (usually works)
npm install

# If npm install hangs due to SSH dependency (environment-specific)
timeout 300 npm install || echo "Install may have timed out, continuing..."

# Do NOT use --omit=optional as it breaks the build
```

**✅ Copilot Environment:** In the Copilot coding environment, `npm install` works reliably without timeouts. The SSH dependency for `@riavzon/botdetector` resolves correctly, and the build process completes successfully.

## Agent Instructions

**Trust these instructions** - they are comprehensive and tested. Only search for additional information if these instructions are incomplete or incorrect. The repository has specific quirks (SSH dependencies, asset file copying, configuration requirements) that are documented here to save exploration time.

**When making changes:**
1. **Always run `npm run build`** after code modifications
2. **Test with `npm run test`** before committing (requires dependencies)
3. **Ensure all asset files are present** in dist/ after build
4. **Be aware of the SSH dependency** when running npm install
5. **Configure the library properly** when testing functionality

**Asset Files Verification:**
After building, these files MUST exist:
- `dist/jwtAuth/emails/system.ejs` (email template)
- `dist/jwtAuth/models/useragent.csv` (user agent data)
- `dist/jwtAuth/utils/disposable_email_blocklist.conf` (email blocklist)
- `dist/global.d.ts` (global type definitions)

**Quick Verification Workflow:**
```bash
# Verify repository state
npm install                   # May timeout on some environments due to SSH dependency
npm run build                 # Full build (requires dependencies, ~2-5 seconds)
npm run test                  # Run test suite (will fail due to missing configuration - expected)
ls dist/jwtAuth/emails/       # Verify email templates copied
ls dist/jwtAuth/models/       # Verify useragent.csv copied
ls dist/jwtAuth/utils/        # Verify email blocklist copied

# If build fails with copy errors:
rm -f tsconfig.tsbuildinfo && npm run build
```

**Expected Results:**
- npm install may hang on botdetector dependency (environment-dependent)
- Full build creates dist/ with all assets copied (emails/, CSV file, config file)
- Test suite fails with configuration error (expected - library requires setup)
- Build process typically completes in 2-5 seconds

**✅ Copilot Environment Results:**
- npm install completes successfully without hanging (SSH dependency works)
- dist/ directory created with all required assets properly copied
- Test suite shows expected configuration error (not a bug)
- Build process completes in ~4 seconds consistently
- All environment tools (MySQL, nginx, curl) are available and functional