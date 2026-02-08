# Development Guide

This document provides comprehensive guidance for developing, testing, and contributing to the JWT Auth Library.

## Table of Contents

- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Development Workflow](#development-workflow)
- [Testing](#testing)
- [Building and Packaging](#building-and-packaging)
- [Code Standards](#code-standards)
- [Contributing](#contributing)
- [Debugging](#debugging)

## Development Setup

### Prerequisites

- **Node.js**: v20.19.4 or higher
- **npm**: v10.8.2 or higher
- **MySQL**: v8.0 or higher
- **Git**: Latest version
- **Docker**: For containerized development (optional)

### Environment Setup

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd auth
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Set up environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your development settings
   ```

4. **Create development database:**
   ```sql
   CREATE DATABASE jwtauth_dev CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   CREATE USER 'dev_user'@'localhost' IDENTIFIED BY 'dev_password';
   GRANT ALL PRIVILEGES ON jwtauth_dev.* TO 'dev_user'@'localhost';
   FLUSH PRIVILEGES;
   ```

5. **Create database tables:**
   ```bash
   npm run build
   npm run build:createTables
   ```

### Development Environment Variables

```bash
# .env for development
NODE_ENV=development

# Database
DB_HOST=localhost
DB_PORT=3306
DB_USER=dev_user
DB_PASS=dev_password
DB_NAME=jwtauth_dev

# JWT (Development keys - NOT for production)
JWT_SECRET=dev-jwt-secret-key-not-for-production
MAGIC_LINKS_SECRET=dev-magic-links-secret-not-for-production
PASSWORD_PEPPER=dev-password-pepper-not-for-production

# Email (Test configuration)
RESEND_API_KEY=test-key
FROM_EMAIL=test@localhost

# Telegram (Optional for development)
TELEGRAM_BOT_TOKEN=test-token
TELEGRAM_CHAT_ID=test-chat
```

## Project Structure

### Source Code Organization

```
src/
├── main.ts                    # Main library exports
├── service.ts                 # Standalone service entry point
├── accessTokens.ts           # Access token utilities
├── refreshTokens.ts          # Refresh token utilities
├── tempLinks.ts              # Magic link utilities
├── anomalies.ts              # Anomaly detection
└── jwtAuth/
    ├── config/               # Configuration management
    │   ├── configuration.ts  # Main config function
    │   └── botDetectorConfig.ts
    ├── controllers/          # Route controllers
    │   ├── loginController.ts
    │   ├── signUpController.ts
    │   ├── OAuth.ts
    │   └── ...
    ├── middleware/           # Express middleware
    │   ├── requireAccessToken.ts
    │   ├── protectRoute.js
    │   ├── verifyJwt.ts
    │   └── ...
    ├── models/               # Database models and schemas
    │   ├── schema.ts         # Database schema
    │   ├── createUser.ts
    │   ├── zodSchema.ts
    │   └── ...
    ├── routes/               # Express routers
    │   ├── auth.ts           # Authentication routes
    │   ├── magicLinks.ts     # Magic link routes
    │   └── TokenRotations.ts # Token management routes
    ├── types/                # TypeScript definitions
    │   ├── configSchema.ts   # Configuration schema
    │   ├── config.ts
    │   └── ...
    ├── utils/                # Utility functions
    │   ├── limiters/         # Rate limiting utilities
    │   ├── hash.ts           # Password hashing
    │   ├── emailMFA.ts       # MFA email handling
    │   └── ...
    └── emails/               # Email templates
        └── system.ejs        # System email template
```

### Test Structure

```
test/
├── setup/                    # Test configuration
│   ├── testConfig.ts        # Database and library setup
│   ├── test.setup.ts        # Global test setup
│   └── vitest.d.ts          # Type definitions
├── accessTokens-test/        # Access token tests
│   ├── generation.test.ts
│   ├── verification.test.ts
│   ├── security.test.ts
│   └── ...
├── refreshTokens-test/       # Refresh token tests
│   ├── generateRefreshToken.test.ts
│   ├── rotateRefreshToken.test.ts
│   └── ...
├── initCustomMfaFlow/        # Custom MFA initialization tests
│   └── init.test.ts
├── verifyCustomMfaController/ # Custom MFA verification tests
│   └── verify.test.ts
└── utils/                    # Utility tests
    └── verifyMfaCode/
        └── verifyMfaCode.test.ts
```

## Development Workflow

### 1. Setting Up for Development

```bash
# Start development environment
npm run build            # Initial build
npm run test            # Run tests to verify setup
npm run docs:dev        # Start documentation server (optional)
```

### 2. Development Cycle

```bash
# Make changes to source code
# Build to compile TypeScript
npm run build

# Run tests
npm test

# Run specific test file
npm test -- jwt-verification.test.ts

# Run tests in watch mode
npm test -- --watch
```

### 3. Documentation Development

```bash
# Start documentation development server
npm run docs:dev        # Live reload at http://localhost:5173

# Build documentation
npm run docs:build      # Static build in .vitepress/dist

# Preview built documentation
npm run docs:preview    # Preview static build
```

## Testing

### Test Configuration

The project uses **Vitest** as the test runner with real database integration (no mocks).

#### Test Database Setup

Tests require a separate test database:

```sql
CREATE DATABASE jwtauth_test CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
GRANT ALL PRIVILEGES ON jwtauth_test.* TO 'dev_user'@'localhost';
```

Set test environment variables:
```bash
# Test environment
DB_HOST=localhost
DB_PORT=3306  
DB_USER=dev_user
DB_PASS=dev_password
DB_NAME=jwtauth_test
```

### Running Tests

#### All Tests
```bash
npm test                    # Run all tests
npm run test:coverage      # Run with coverage report
npm run test:ui            # Run with UI interface
```

#### Specific Tests
```bash
# Run specific test file
npm test -- jwt-verification.test.ts

# Run tests matching pattern
npm test -- --grep "access token"

# Run tests in specific directory
npm test -- test/accessTokens-test/
```

#### Watch Mode
```bash
npm test -- --watch       # Watch for changes and re-run tests
```

### Writing Tests

#### Test Structure Example

```typescript
// test/accessTokens-test/example.test.ts
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { generateAccessToken, verifyAccessToken } from '../../src/accessTokens.js';
import { setupTestConfiguration, createTestUser, cleanupTestDatabase } from '../setup/testConfig.js';

describe('Access Token Generation', () => {
  beforeEach(async () => {
    setupTestConfiguration();
  });

  afterEach(async () => {
    await cleanupTestDatabase();
  });

  it('should generate valid access token', async () => {
    const userId = await createTestUser('test@example.com');
    const visitorId = 'test-visitor-id';
    
    const token = await generateAccessToken(userId, visitorId);
    
    expect(token).toBeDefined();
    expect(typeof token).toBe('string');
    
    // Verify token is valid
    const decoded = await verifyAccessToken(token);
    expect(decoded.userId).toBe(userId);
    expect(decoded.visitor_id).toBe(visitorId);
  });
});
```

#### Test Best Practices

1. **Use Real Database**: Tests use actual MySQL database, not mocks
2. **Clean State**: Each test starts with clean database state
3. **Async/Await**: Use async/await for all database operations
4. **Descriptive Names**: Test names should clearly describe what's being tested
5. **Edge Cases**: Test both success and failure scenarios

### Test Coverage

```bash
npm run test:coverage

# Coverage report is generated in coverage/ directory
# View HTML report: open coverage/index.html
```

Target coverage goals:
- **Statements**: >90%
- **Branches**: >85%
- **Functions**: >90%
- **Lines**: >90%

## Building and Packaging

### Build Process

The build process involves TypeScript compilation and asset copying:

```bash
npm run build
```

This runs:
1. `tsc -p tsconfig.json` - TypeScript compilation
2. Copy email templates: `cp -R src/jwtAuth/emails dist/jwtAuth`
3. Copy configuration files: `cp src/jwtAuth/utils/disposable_email_blocklist.conf dist/jwtAuth/utils`
4. Copy data files: `cp src/jwtAuth/models/useragent.csv dist/jwtAuth/models`

### Production Build

```bash
npm run build:prod        # Uses tsconfig.prod.json for optimized build
```

### Build Output

```
dist/
├── main.js               # Main library entry point
├── main.d.ts            # Type definitions
├── service.js           # Service entry point
├── accessTokens.js      # Compiled utilities
└── jwtAuth/
    ├── config/          # Compiled configuration
    ├── controllers/     # Compiled controllers
    ├── middleware/      # Compiled middleware
    ├── models/          # Compiled models + CSV data
    ├── routes/          # Compiled routes
    ├── types/           # Compiled types
    ├── utils/           # Compiled utilities + config files
    └── emails/          # Email templates (copied)
```

### Package Preparation

```bash
npm run prepack          # Automatically runs build
npm pack                 # Create .tgz package
```

## Code Standards

### TypeScript Configuration

The project uses strict TypeScript configuration:

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "outDir": "./dist",
    "incremental": true
  }
}
```

### Code Style Guidelines

#### File Naming
- **Modules**: camelCase (e.g., `accessTokens.ts`)
- **Classes**: PascalCase (e.g., `UserManager.ts`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `MAX_SESSIONS`)

#### Function Naming
```typescript
// Use descriptive names
export async function generateAccessToken(userId: number, visitorId: string): Promise<string>

// Use verb-noun pattern
export async function verifyEmailAddress(email: string): Promise<boolean>

// Use consistent naming for similar operations
export async function createUser(userData: UserData): Promise<User>
export async function createOauthUser(providerData: OAuthData): Promise<User>
```

#### Type Definitions
```typescript
// Use interfaces for object shapes
interface UserProfile {
  id: number;
  email: string;
  name: string;
  createdAt: Date;
}

// Use type aliases for unions and complex types
type AuthProvider = 'google' | 'github' | 'facebook';
type TokenType = 'access' | 'refresh' | 'magic';

// Export types for public API
export type { UserProfile, AuthProvider };
```

#### Error Handling
```typescript
// Use specific error types
class AuthenticationError extends Error {
  constructor(message: string, public code: string) {
    super(message);
    this.name = 'AuthenticationError';
  }
}

// Consistent error handling pattern
export async function loginUser(email: string, password: string): Promise<LoginResult> {
  try {
    // Implementation
    return { success: true, user, tokens };
  } catch (error) {
    if (error instanceof AuthenticationError) {
      return { success: false, error: error.code };
    }
    throw error; // Re-throw unexpected errors
  }
}
```

### Documentation Standards

#### JSDoc Comments
```typescript
/**
 * Generates a new access token for the specified user.
 * 
 * @param userId - The unique identifier of the user
 * @param visitorId - The visitor session identifier
 * @param options - Optional token configuration
 * @returns Promise resolving to the signed JWT token
 * 
 * @throws {Error} When token generation fails
 * 
 * @example
 * ```typescript
 * const token = await generateAccessToken(123, 'visitor_abc');
 * console.log(token); // "eyJhbGciOiJIUzI1NiIs..."
 * ```
 */
export async function generateAccessToken(
  userId: number, 
  visitorId: string,
  options?: TokenOptions
): Promise<string>
```

#### README Documentation
- Always update README when adding new features
- Include usage examples for new functionality
- Update configuration documentation when adding new options

## Contributing

### Getting Started

1. **Fork the repository**
2. **Create feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
4. **Add tests for new functionality**
5. **Run the test suite:**
   ```bash
   npm test
   npm run build
   ```

6. **Submit pull request**

### Pull Request Guidelines

#### Before Submitting
- [ ] All tests pass (`npm test`)
- [ ] Build succeeds (`npm run build`)
- [ ] Documentation updated
- [ ] Type definitions exported if needed
- [ ] Changes are backwards compatible

#### PR Description Template
```markdown
## Description
Brief description of the changes.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing
- [ ] Tests added for new functionality
- [ ] All existing tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows the style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No breaking changes (or properly documented)
```

### Code Review Process

1. **Automated Checks**: CI runs tests and builds
2. **Manual Review**: Maintainer reviews code quality and design
3. **Feedback Integration**: Address review comments
4. **Approval**: Maintainer approves and merges

## Debugging

### Development Debugging

#### Enable Debug Logging
```typescript
configuration({
  // ... other config
  logLevel: 'debug'  // Enables verbose logging
});
```

#### Database Query Debugging
```typescript
// Add to your development config
const pool = mysql.createPool({
  // ... connection config
  debug: true,        // Log all SQL queries
  trace: true         // Include stack traces
});
```

#### Token Debugging
```typescript
import { verifyAccessToken } from './src/accessTokens.js';

// Debug token contents
const token = "eyJhbGciOiJIUzI1NiIs...";
try {
  const decoded = await verifyAccessToken(token);
  console.log('Token payload:', decoded);
} catch (error) {
  console.error('Token validation failed:', error);
}
```

### Testing Debugging

#### Run Single Test with Debug
```bash
# Enable debug logging in test
DEBUG=* npm test -- specific.test.ts

# Run test with node inspector
node --inspect-brk ./node_modules/.bin/vitest run specific.test.ts
```

#### Database State Inspection
```typescript
// In test files, inspect database state
it('should create user correctly', async () => {
  const userId = await createTestUser('test@example.com');
  
  // Debug: Check database state
  const [users] = await testPool.execute('SELECT * FROM users WHERE id = ?', [userId]);
  console.log('Created user:', users[0]);
  
  // Your test assertions...
});
```

### Production Debugging

#### Log Analysis
```bash
# Monitor logs in real-time
docker logs -f jwtauth

# Search for specific errors
docker logs jwtauth 2>&1 | grep "ERROR"

# Filter by timestamp
docker logs jwtauth --since="2023-12-15T10:00:00"
```

#### Performance Debugging
```bash
# Monitor resource usage
docker stats jwtauth

# Check database connections
mysql -e "SHOW PROCESSLIST;" jwtauth_production
```

### Common Issues and Solutions

#### Build Issues
```bash
# Clear TypeScript cache
rm -f tsconfig.tsbuildinfo
npm run build

# Clear node_modules and reinstall
rm -rf node_modules package-lock.json
npm install
```

#### Test Issues
```bash
# Database connection failures
# Check MySQL is running
sudo systemctl status mysql

# Check test database exists
mysql -e "SHOW DATABASES LIKE 'jwtauth_test';"

# Reset test database
mysql -e "DROP DATABASE IF EXISTS jwtauth_test; CREATE DATABASE jwtauth_test;"
npm run build:createTables
```

#### Runtime Issues
```bash
# Missing configuration
# Ensure all required config sections are present
node -e "console.log(JSON.stringify(require('./config.json'), null, 2))"

# Database connectivity
# Test database connection
mysql -h $DB_HOST -u $DB_USER -p$DB_PASS $DB_NAME -e "SELECT 1;"
```

## Development Tools

### Recommended VS Code Extensions

- **TypeScript**: Built-in TypeScript support
- **Vitest**: Test runner integration
- **MySQL**: Database connectivity and query tools
- **Docker**: Container development support
- **GitLens**: Enhanced Git integration

### Useful Scripts

```bash
# Development workflow
npm run dev:setup       # Set up development environment
npm run dev:reset       # Reset development database
npm run dev:seed        # Seed test data

# Quality checks
npm run type-check      # TypeScript type checking
npm run lint           # Code linting (if configured)
npm run format         # Code formatting (if configured)

# Database management
npm run db:migrate     # Run database migrations
npm run db:seed        # Seed development data
npm run db:reset       # Reset development database
```

### Environment Management

Use different configurations for different environments:

```bash
# development.config.json
{
  "logLevel": "debug",
  "jwt": {
    "access_tokens": { "expiresIn": "1h" }
  }
}

# test.config.json  
{
  "logLevel": "error",
  "jwt": {
    "access_tokens": { "expiresIn": "5m" }
  }
}

# Load based on NODE_ENV
const configFile = `${process.env.NODE_ENV || 'development'}.config.json`;
```

This development guide provides everything needed to effectively contribute to and maintain the JWT Auth Library. For specific implementation questions, refer to the TypeScript definitions and JSDoc comments throughout the codebase.
