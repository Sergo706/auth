# Unit Tests for Auth Library

This directory contains comprehensive unit tests for the authentication library, focusing on access tokens and refresh tokens functionality.

## Test Files

### 1. `jwts.test.ts` - Access Token Tests
Tests for functions in `src/accessTokens.ts`:

#### `generateAccessToken` Function
- ✅ **Valid JWT Generation**: Verifies that generated tokens follow JWT structure (header.payload.signature)
- ✅ **Payload Verification**: Ensures all required claims are included (visitor_id, roles, custom payload, etc.)
- ✅ **Role Handling**: Tests both with and without user roles
- ✅ **Configuration Integration**: Verifies custom payload from configuration is included
- ✅ **Token Uniqueness**: Ensures different users generate different tokens
- ✅ **Expiration Time**: Validates tokens have correct expiration time (15 minutes default)

#### `verifyAccessToken` Function  
- ✅ **Cache Validation**: Tests token cache lookup and validation
- ✅ **Invalid Cache Handling**: Tests missing or invalid cache entries
- ✅ **Valid Token Verification**: Tests successful token verification
- ✅ **Visitor ID Mismatch**: Tests detection of visitor ID mismatches
- ✅ **Malformed Token Handling**: Tests graceful handling of malformed JWTs
- ✅ **Role Validation**: Tests role-based access control validation

### 2. `refreshTokens.test.ts` - Refresh Token Tests
Tests for functions in `src/refreshTokens.ts`:

#### `generateRefreshToken` Function
- ✅ **Token Structure**: Verifies correct structure (raw token, hashed token, expiration)
- ✅ **Token Format**: Validates token format (128 hex chars for raw, 64 for hash)
- ✅ **Expiration Calculation**: Tests correct TTL calculation
- ✅ **Token Uniqueness**: Ensures multiple calls generate unique tokens
- ✅ **Database Integration**: Verifies correct database insertion
- ✅ **Error Handling**: Tests database error scenarios
- ✅ **Hash Validation**: Verifies SHA256 hashing is correct

#### `verifyRefreshToken` Function
- ✅ **Valid Token Verification**: Tests successful token verification
- ✅ **Hash Flag Handling**: Tests both raw and pre-hashed token inputs
- ✅ **Non-existent Token**: Tests handling of tokens not in database
- ✅ **Revoked Token Handling**: Tests detection and deletion of revoked tokens
- ✅ **Expired Token Handling**: Tests token expiration detection and invalidation
- ✅ **Database Error Handling**: Tests graceful error handling

#### `consumeAndVerifyRefreshToken` Function (One-time Use)
- ✅ **Successful Consumption**: Tests one-time token consumption
- ✅ **Transaction Handling**: Verifies proper database transaction usage
- ✅ **Already Used Detection**: Tests handling of already consumed tokens
- ✅ **Token Revocation**: Tests revocation of all user tokens on reuse
- ✅ **Expiration During Consumption**: Tests token expiration handling
- ✅ **Rollback on Error**: Tests transaction rollback on database errors

#### `rotateRefreshToken` Function
- ✅ **Successful Rotation**: Tests token rotation with new token generation
- ✅ **Hash Flag Support**: Tests both raw and pre-hashed old token inputs
- ✅ **Old Token Not Found**: Tests handling when old token doesn't exist
- ✅ **Database Error Handling**: Tests error scenarios during rotation

#### `revokeRefreshToken` Function
- ✅ **Successful Revocation**: Tests token revocation functionality
- ✅ **Hash Flag Support**: Tests both raw and pre-hashed token inputs
- ✅ **Database Error Handling**: Tests graceful error handling
- ✅ **Missing Token Handling**: Tests behavior when token doesn't exist

### 3. `tokenUtils.test.ts` - Utility and Integration Tests
Utility tests for core token functionality:

#### Crypto Token Generation
- ✅ **Unique Token Generation**: Verifies cryptographic randomness
- ✅ **Consistent Hashing**: Tests SHA256 hash consistency
- ✅ **Hash Uniqueness**: Verifies different inputs produce different hashes

#### UUID Generation
- ✅ **Valid UUID Format**: Tests UUID v4 format compliance
- ✅ **UUID Uniqueness**: Verifies UUID uniqueness

#### Date Handling
- ✅ **Expiration Calculation**: Tests TTL calculations
- ✅ **Expiry Detection**: Tests expired token identification

#### JWT Structure Validation
- ✅ **JWT Format**: Tests proper JWT structure validation
- ✅ **Malformed Token Handling**: Tests various malformed token scenarios

#### Token Payload Validation
- ✅ **Required Fields**: Tests payload field validation
- ✅ **Optional Fields**: Tests optional role field handling
- ✅ **Role Array Validation**: Tests role array structure validation

#### Security Properties
- ✅ **Cryptographic Strength**: Tests token randomness and uniqueness
- ✅ **Hash Consistency**: Tests hash function reliability

## Test Features

### Mocking Strategy
- **Configuration**: Mocked to provide consistent test environment
- **Database**: Mocked pool and connection for isolated testing
- **Logger**: Mocked to prevent log output during tests
- **Token Cache**: Mocked LRU cache for controlled testing

### Test Coverage
- **Happy Path**: All successful scenarios are tested
- **Error Handling**: Database errors, invalid inputs, expired tokens
- **Edge Cases**: Malformed tokens, missing data, concurrent access
- **Security**: Token uniqueness, cryptographic strength, proper hashing

### Test Organization
- **Descriptive Names**: Each test clearly describes what it validates
- **Grouped by Function**: Tests organized by the function they test
- **Clear Assertions**: Each test has clear, verbose assertions
- **Setup/Cleanup**: Proper mock setup and cleanup between tests

## Running the Tests

```bash
# Run all tests
npm test

# Run specific test file
npx vitest tests/jwts.test.ts
npx vitest tests/refreshTokens.test.ts
npx vitest tests/tokenUtils.test.ts

# Run with coverage
npx vitest --coverage
```

## Test Dependencies

The tests use:
- **Vitest**: Modern testing framework
- **Node.js crypto**: For cryptographic operations
- **Mock functions**: For dependency isolation

## Notes

- Tests are designed to be fast and deterministic
- No real database or external dependencies required
- Comprehensive error scenario coverage
- Validates both functional requirements and security properties
- Follows the existing codebase patterns and conventions