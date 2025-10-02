# API Reference

This document provides comprehensive API documentation for all endpoints exposed by the JWT Auth Library.

## Table of Contents

- [Overview](#overview)
- [Authentication Routes](#authentication-routes)
- [Token Management Routes](#token-management-routes)
- [Magic Link Routes](#magic-link-routes)
- [Middleware](#middleware)
- [Error Responses](#error-responses)
- [Rate Limiting](#rate-limiting)

## Overview

The JWT Auth Library exposes three main route groups and several middleware functions for Express.js applications.

### Base Configuration

```typescript
import { authenticationRoutes, tokenRotationRoutes, magicLinks } from '@riavzon/jwtauth';

app.use(authenticationRoutes);           // Core authentication
app.use('/token', tokenRotationRoutes);  // Token management  
app.use(magicLinks);                     // Magic links
```

Responses vary by endpoint. See the examples in each section.

## Authentication Routes

### POST /signup

Create a new user account.

**Request Body:**
```typescript
{
  Name: string,                         // 1–4 names, letters only (comma/space separated)
  email: string,
  password: string,                     // 12–64 chars, mixed case, digit and special char
  confirmedPassword: string,            // must match password
  rememberUser?: "on",                 // optional; string literal transformed to boolean
  termsConsent?: "on"                  // optional; string literal transformed to boolean
}
```

**Example Request:**
```bash
curl -X POST http://localhost:3000/signup \
  -H "Content-Type: application/json" \
  -d '{
    "Name": "John Doe",
    "email": "john.doe@example.com",
    "password": "SecurePassword123!",
    "confirmedPassword": "SecurePassword123!",
    "termsConsent": "on"
  }'
```

**Success Response (201):**
```json
{
  "ok": true,
  "receivedAt": "2025-01-01T12:00:00.000Z",
  "accessToken": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...",
  "banned": false,
  "accessIat": "1735728000000"
}
```

**Error Responses:**
- `400` - Validation errors (invalid email, weak password, etc.)
- `409` - Email already exists
- `429` - Rate limit exceeded

### POST /login

Authenticate user and receive tokens.

**Request Body:**
```typescript
{
  email: string,
  password: string
}
```

**Example Request:**
```bash
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "SecurePassword123!",
    "remember_user": true
  }'
```

**Success Response (200):**
```json
{
  "ok": true,
  "receivedAt": "2025-01-01T12:00:00.000Z",
  "accessToken": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...",
  "banned": false,
  "accessIat": "1735728000000"
}
```

Note: MFA enforcement occurs when accessing protected routes via `protectRoute`; login itself does not return an MFA challenge.

**Error Responses:**
- `400` - Invalid request format
- `401` - Invalid credentials
- `429` - Rate limit exceeded
- `423` - Account temporarily locked

### POST /auth/OAuth/:providerName

OAuth authentication with third-party providers.

**URL Parameters:**
- `providerName` - OAuth provider identifier (e.g., "google", "github"). Routing is case-insensitive by default.

**Request Body:**
```typescript
{
  userInfo: unknown // Provider-specific profile payload validated via Zod schema
}
```

**Example Request:**
```bash
curl -X POST http://localhost:3000/auth/OAuth/google \
  -H "Content-Type: application/json" \
  -d '{
    "userInfo": {
      "sub": "google_user_id",
      "email": "john.doe@gmail.com",
      "email_verified": true,
      "given_name": "John",
      "family_name": "Doe",
      "picture": "https://example.com/avatar.jpg"
    }
  }'
```

**Success Response (200):**
```json
{
  "ok": true,
  "receivedAt": "2025-01-01T12:00:00.000Z",
  "accessToken": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...",
  "banned": false,
  "accessIat": "1735728000000"
}
```

**Error Responses:**
- `400` - Invalid or unrecognized provider payload
- `401` - OAuth authentication failed
- `404` - Provider not supported
- `429` - Rate limit exceeded

## Token Management Routes

By default these routes are available under `/auth/*` when the router is mounted without a prefix. If you mount with a prefix (e.g., `app.use('/token', tokenRotationRoutes)`), final routes become `/token/auth/*`.

### POST /auth/refresh-access

Refresh an expired access token using a valid refresh token.

**Headers:**
```
Authorization: Bearer <refresh_token>
```

**Example Request:**
```bash
curl -X POST http://localhost:3000/auth/refresh-access \
  -H "Authorization: Bearer rt_xxxxxxxxxxxxxxxxxxxxxxxx"
```

**Success Response (200):**
```json
{
  "ok": true,
  "access_token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 900
}
```

**Error Responses:**
- `401` - Invalid or expired refresh token
- `403` - Token revoked or user deactivated
- `429` - Rate limit exceeded

### POST /auth/user/refresh-session

Rotate refresh token and issue new session tokens.

**Headers:**
```
Authorization: Bearer <refresh_token>
```

**Example Request:**
```bash
curl -X POST http://localhost:3000/auth/user/refresh-session \
  -H "Authorization: Bearer rt_xxxxxxxxxxxxxxxxxxxxxxxx"
```

**Success Response (200):**
```json
{
  "ok": true,
  "access_token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "rt_yyyyyyyyyyyyyyyyyyyyyyyy",
  "expires_in": 900
}
```

**Error Responses:**
- `401` - Invalid refresh token
- `403` - Maximum sessions exceeded
- `429` - Rate limit exceeded

### POST /auth/logout

Revoke the current refresh token and end the session.

**Headers:**
```
Authorization: Bearer <refresh_token>
```

**Example Request:**
```bash
curl -X POST http://localhost:3000/auth/logout \
  -H "Authorization: Bearer rt_xxxxxxxxxxxxxxxxxxxxxxxx"
```

**Success Response (200):**
```json
{
  "ok": true,
  "message": "Logged out successfully"
}
```

### POST /auth/refresh-session/rotate-every

Rotate access and refresh tokens in one operation.

**Headers:**
```
Authorization: Bearer <refresh_token>
```

This endpoint is available when `rotateOnEveryAccessExpiry` is enabled; it enforces `acceptCookieOnly` semantics (no body, no content-type, bearer auth, session cookie required).

**Error Responses:**
- `401` - Invalid refresh token
- `404` - Token not found

## Magic Link Routes

### POST /auth/forgot-password

Initiate password reset flow by sending a magic link via email.

**Request Body:**
```typescript
{
  email: string
}
```

**Example Request:**
```bash
curl -X POST http://localhost:3000/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com"
  }'
```

**Success Response (200):**
```json
{
  "success": true,
  "message": "Password reset link sent to your email"
}
```

**Error Responses:**
- `400` - Invalid email format
- `404` - Email not found
- `429` - Rate limit exceeded

### GET /auth/reset-password/:visitor

Validate a password reset link (no token issuance).

**URL Parameters:**
- `visitor` - Magic link visitor token

**Success Response (200):**
```json
{ "link": "Password Reset" }
```

### POST /auth/reset-password/:visitor

Complete password reset using magic link token.

**URL Parameters:**
- `visitor` - Magic link visitor token

**Request Body:**
```typescript
{
  password: string,
  confirm_password: string
}
```

**Example Request:**
```bash
curl -X POST http://localhost:3000/auth/reset-password/ml_xxxxxxxxxx \
  -H "Content-Type: application/json" \
  -d '{
    "password": "NewSecurePassword123!",
    "confirm_password": "NewSecurePassword123!"
  }'
```

**Success Response (200):**
```json
{
  "success": true,
  "message": "Password reset successfully"
}
```

**Error Responses:**
- `400` - Password validation failed or passwords don't match
- `401` - Invalid or expired magic link
- `404` - Magic link not found
- `429` - Rate limit exceeded

### GET /auth/verify-mfa/:visitor

Validate an MFA link (no token issuance).

**URL Parameters:**
- `visitor` - MFA verification token

**Example Request:**
```bash
curl -X GET http://localhost:3000/auth/verify-mfa/mfa_xxxxxxxxxx
```

**Success Response (200):**
```json
{ "link": "MFA Code" }
```

**Error Responses:**
- `401` - Invalid or expired MFA token
- `404` - MFA token not found
- `429` - Rate limit exceeded

### POST /auth/verify-mfa/:visitor

Verify MFA using the provided code in the request body. On success, sets new cookies and returns an access token.

**Request Body:**
```json
{ "code": "123456" }
```

**Success Response (200):**
```json
{
  "accessToken": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...",
  "accessIat": "1735728000000"
}
```

## Middleware

### requireAccessToken

Middleware that validates the presence and format of an access token.

```typescript
import { requireAccessToken } from '@riavzon/jwtauth';

app.get('/protected', requireAccessToken, (req, res) => {
  // Access token validated and available
});
```

**Headers Required:**
```
Authorization: Bearer <access_token>
```

### requireRefreshToken

Middleware that validates the presence and format of a refresh token.

```typescript
import { requireRefreshToken } from '@riavzon/jwtauth';

app.post('/sensitive', requireRefreshToken, (req, res) => {
  // Refresh token validated and available
});
```

**Headers Required:**
```
Authorization: Bearer <refresh_token>
```

### protectRoute

Middleware that verifies JWT tokens and populates `req.user`.

```typescript
import { protectRoute, requireAccessToken } from '@riavzon/jwtauth';

app.get('/profile', requireAccessToken, protectRoute, (req, res) => {
  // req.user contains validated token payload
  const { userId, visitor_id, accessTokenId } = req.user;
  res.json({ userId });
});
```

**Populates `req.user` with:**
```typescript
{
  userId: number,
  visitor_id: string,
  accessTokenId: string,
  iat: number,
  exp: number
}
```

### validateContentType

Middleware that validates request content type.

```typescript
import { validateContentType } from '@riavzon/jwtauth';

app.post('/api/*', validateContentType, (req, res) => {
  // Content-Type validated
});
```

### acceptCookieOnly

Middleware that restricts requests to cookie-based authentication only.

```typescript
import { acceptCookieOnly } from '@riavzon/jwtauth';

app.post('/secure', acceptCookieOnly, (req, res) => {
  // Only cookie-based auth accepted
});
```

## Error Responses

### Standard Error Format

```json
{
  "success": false,
  "error": "ERROR_CODE",
  "message": "Human-readable error message"
}
```

### Common Error Codes

| Code | Description | HTTP Status |
|------|-------------|-------------|
| `VALIDATION_ERROR` | Request validation failed | 400 |
| `INVALID_CREDENTIALS` | Wrong email/password | 401 |
| `UNAUTHORIZED` | Missing or invalid token | 401 |
| `ACCESS_DENIED` | Insufficient permissions | 403 |
| `NOT_FOUND` | Resource not found | 404 |
| `CONFLICT` | Resource already exists | 409 |
| `RATE_LIMITED` | Rate limit exceeded | 429 |
| `INTERNAL_ERROR` | Server error | 500 |

### Validation Errors

Validation errors include detailed field information:

```json
{
  "success": false,
  "error": "VALIDATION_ERROR",
  "message": "Validation failed",
  "details": [
    {
      "field": "email",
      "message": "Invalid email format"
    },
    {
      "field": "password",
      "message": "Password must be at least 8 characters"
    }
  ]
}
```

## Rate Limiting

### Rate Limit Headers

All responses include rate limiting headers:

```
Retry-After: 300
```

### Rate Limit Exceeded Response

```json
{
  "success": false,
  "error": "Too many requests",
  "retry": 300
}
```

### Rate Limiting Scopes

Different endpoints have different rate limiting scopes:

| Endpoint | Scope | Limit |
|----------|-------|-------|
| `/login` | IP + Email | 5/min, 15/15min |
| `/signup` | IP + Email | 3/hour, 10/day |
| `/auth/OAuth/*` | IP + Provider | 5/min, 15/15min |
| `/auth/*` | User + IP | 10/5min, 50/hour |
| `/auth/forgot-password` | Email + IP | 3/30min, 5/12hour |
| `/auth/reset-password/*` | IP | 5/10min |

## Health Check

### GET /health

Service health check endpoint.

**Example Request:**
```bash
curl -X GET http://localhost:3000/health
```

**Success Response (200):**
```
OK
```

This endpoint is used by Docker health checks and load balancers.

## Authentication Flow Examples

### Complete Login Flow

```bash
# 1. Login
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password"}'

# Response includes access_token and refresh_token

# 2. Access protected resource
curl -X GET http://localhost:3000/protected \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."

# 3. Refresh access token when expired
curl -X POST http://localhost:3000/auth/refresh-access \
  -H "Authorization: Bearer rt_xxxxxxxxxxxxxxxxxxxxxxxx"

# 4. Logout
curl -X POST http://localhost:3000/auth/logout \
  -H "Authorization: Bearer rt_xxxxxxxxxxxxxxxxxxxxxxxx"
```

### MFA Flow

```bash
# 1. Login (triggers MFA)
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password"}'

# Response: {"mfa_required": true, "visitor_id": "visitor_xxx"}

# 2. User receives email with MFA link
# 3. User clicks link or app calls verification endpoint
curl -X GET http://localhost:3000/auth/verify-mfa/mfa_xxxxxxxxxx

# Response includes final access_token and refresh_token
```

### Password Reset Flow

```bash
# 1. Request password reset
curl -X POST http://localhost:3000/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'

# 2. User receives email with reset link
# 3. Use reset link to set new password
curl -X POST http://localhost:3000/auth/reset-password/ml_xxxxxxxxxx \
  -H "Content-Type: application/json" \
  -d '{
    "password": "NewPassword123!",
    "confirm_password": "NewPassword123!"
  }'
```

## Best Practices

### Token Management
1. **Store access tokens securely** - Use secure storage mechanisms
2. **Handle token expiry gracefully** - Implement automatic refresh logic
3. **Respect rate limits** - Implement exponential backoff
4. **Use HTTPS only** - Never transmit tokens over HTTP

### Error Handling
1. **Parse error responses** - Check the `ok` field (or endpoint-specific shape)
2. **Handle rate limiting** - Respect `Retry-After` header and JSON `retry` field
3. **Implement fallbacks** - Graceful degradation for auth failures
4. **Log security events** - Monitor for unusual authentication patterns

### Security
1. **Validate all inputs** - Don't trust client-side validation
2. **Implement CSRF protection** - Add CSRF at the client/gateway when using the service
3. **Monitor for abuse** - Watch for unusual patterns
4. **Keep tokens short-lived** - Regular token rotation
