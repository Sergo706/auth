# RefreshTokens.ts Testing Documentation

This document describes the comprehensive testing suite created for the `refreshTokens.ts` file in the JWT authentication library.

## Overview

The testing suite provides complete coverage of all functions in `refreshTokens.ts` with both real database integration tests and mock tests for scenarios where database connectivity is not available.

## Test Files

### 1. `refreshTokens.test.ts` - Integration Tests (38 tests)
Complete integration tests using real MySQL database connectivity.

**Functions Tested:**
- `generateRefreshToken()` - 6 test cases
- `rotateRefreshToken()` - 6 test cases  
- `verifyRefreshToken()` - 6 test cases
- `consumeAndVerifyRefreshToken()` - 6 test cases
- `revokeRefreshToken()` - 5 test cases
- Security Tests - 4 test cases
- Edge Cases and Error Handling - 4 test cases

### 2. `refreshTokens.mock.test.ts` - Mock Tests (9 tests)
Mock implementations for testing without database dependencies.

### 3. `testConfig.ts` - Test Configuration
Database connection setup and test utilities.

### 4. `setupTestDB.ts` - Database Setup
Creates the necessary database tables for testing.

## Prerequisites

1. **MySQL Server** running on `127.0.0.1:3306`
2. **Database:** `app_db` 
3. **Credentials:** `root` / `1234`
4. **Node.js 20+** with npm

## Setup Instructions

### 1. Install Dependencies
```bash
npm install
```

### 2. Build the Project
```bash
npm run build
```

### 3. Setup Test Database
```bash
npx tsx tests/setupTestDB.ts
```

### 4. Run Tests

#### Run Integration Tests (with database)
```bash
npm test refreshTokens.test.ts
```

#### Run Mock Tests (without database)
```bash
npm test refreshTokens.mock.test.ts
```

#### Run All Tests
```bash
npm test
```

## Test Coverage

### Function Coverage

#### `generateRefreshToken(ttl, userId)`
- ✅ Valid token generation with correct structure
- ✅ Consistent SHA256 hashing
- ✅ Proper database storage
- ✅ Different TTL value handling
- ✅ Error handling for invalid user IDs
- ✅ Unique token generation for same user

#### `rotateRefreshToken(ttl, userId, oldToken, hashed?)`
- ✅ Successful token rotation
- ✅ Database record updates
- ✅ Pre-hashed token support
- ✅ Non-existent token handling
- ✅ User ownership verification
- ✅ Invalid user ID handling

#### `verifyRefreshToken(clientToken, hashed?)`
- ✅ Valid token verification
- ✅ Pre-hashed token support
- ✅ Usage count increment
- ✅ Expired token rejection and cleanup
- ✅ Non-existent token handling
- ✅ Revoked token detection and deletion

#### `consumeAndVerifyRefreshToken(clientToken, hashed?)`
- ✅ Successful token consumption
- ✅ Token reuse attack detection
- ✅ Pre-hashed token support
- ✅ Expired token handling
- ✅ Revoked token handling
- ✅ Non-existent token handling
- ✅ Transaction integrity

#### `revokeRefreshToken(clientToken, hashed?)`
- ✅ Successful token revocation
- ✅ Pre-hashed token support
- ✅ Already revoked token handling
- ✅ Non-existent token handling
- ✅ Selective token revocation

### Security Testing

#### SQL Injection Prevention
- ✅ Malicious SQL injection attempts blocked
- ✅ Parameterized queries protect against injection
- ✅ Table structure integrity maintained

#### Token Reuse Detection
- ✅ Double usage detection for `consumeAndVerifyRefreshToken`
- ✅ Automatic security response (token revocation)
- ✅ Suspicious pattern recognition

#### Session Security
- ✅ Concurrent operation safety
- ✅ Token format validation
- ✅ Length validation
- ✅ Character validation

### Edge Case Testing

#### Error Handling
- ✅ Database connection failures
- ✅ Invalid parameters
- ✅ Extremely large TTL values
- ✅ Zero and negative TTL values
- ✅ Special characters in tokens

#### Transaction Safety
- ✅ Rollback on errors
- ✅ Atomic operations
- ✅ Consistency maintenance

## Database Schema

The tests use the following database tables:

```sql
-- Visitors table for tracking user sessions
CREATE TABLE visitors (
    visitor_id INT AUTO_INCREMENT UNIQUE NOT NULL,
    canary_id VARCHAR(64) PRIMARY KEY,
    ip_address VARCHAR(45),
    user_agent TEXT,
    -- ... additional fields
);

-- Users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    visitor_id INT,
    FOREIGN KEY (visitor_id) REFERENCES visitors(visitor_id)
);

-- Refresh tokens table
CREATE TABLE refresh_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(64) UNIQUE NOT NULL,
    valid BOOLEAN DEFAULT TRUE,
    expiresAt DATETIME NOT NULL,
    usage_count INT DEFAULT 0,
    session_started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

## Configuration

The test environment uses a minimal but complete configuration:

```typescript
configuration({
  store: {
    main: promisePool,           // MySQL2 promise pool
    rate_limiters_pool: {
      store: callbackPool,       // MySQL2 callback pool  
      dbName: 'app_db'
    }
  },
  jwt: {
    jwt_secret_key: 'test-secret',
    access_tokens: { expiresIn: '15m' },
    refresh_tokens: {
      rotateOnEveryAccessExpiry: true,
      refresh_ttl: 7 * 24 * 60 * 60 * 1000, // 7 days
      domain: 'localhost',
      MAX_SESSION_LIFE: 30 * 24 * 60 * 60 * 1000,
      maxAllowedSessionsPerUser: 5,
      byPassAnomaliesFor: 24 * 60 * 60 * 1000
    }
  },
  // ... other required config
});
```

## Test Results

When all tests pass, you should see:

```
✓ tests/refreshTokens.test.ts (38 tests) 
✓ tests/refreshTokens.mock.test.ts (9 tests)

Test Files  2 passed (2)
Tests  47 passed (47)
```

## Troubleshooting

### Common Issues

1. **MySQL Connection Error**
   - Ensure MySQL is running on `127.0.0.1:3306`
   - Verify credentials: `root` / `1234`
   - Check database `app_db` exists

2. **Foreign Key Constraint Errors**
   - Run database cleanup manually: `DELETE FROM refresh_tokens; DELETE FROM users WHERE email LIKE '%test%';`
   - Re-run setup: `npx tsx tests/setupTestDB.ts`

3. **Configuration Errors**
   - Ensure all required configuration fields are provided
   - Check that domain format is valid URL

4. **Build Errors**
   - Run `npm run build` before testing
   - Ensure all dependencies are installed

## Security Considerations

The test suite validates several critical security aspects:

1. **Token Reuse Prevention**: Critical for preventing session hijacking
2. **SQL Injection Protection**: Ensures parameterized queries are used
3. **Transaction Integrity**: Prevents partial updates that could compromise security
4. **Input Validation**: Proper handling of malformed tokens
5. **Concurrent Access**: Safe handling of simultaneous token operations

## Mock Testing

The mock tests provide an alternative when database connectivity is not available. They test:

- Token generation logic
- Validation algorithms  
- Security patterns
- Error handling
- Edge cases

Mock tests run completely independently and don't require any external dependencies.

## Performance

The integration tests are designed to run efficiently:

- Database cleanup between test cases
- Connection pooling for performance
- Minimal test data creation
- Proper resource cleanup

Typical execution time: ~1-2 seconds for all 47 tests.