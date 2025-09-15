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

### Common Response Format

All endpoints return JSON responses with consistent structure:

```typescript
{
  success: boolean,
  data?: any,
  error?: string,
  message?: string
}
```

## Authentication Routes

### POST /signup

Create a new user account.

**Request Body:**
```typescript
{
  name: string,
  last_name: string,
  email: string,
  password: string,
  remember_user?: boolean,
  terms_and_privacy_agreement?: boolean,
  accepts_marketing?: boolean,
  country?: string,
  city?: string,
  address?: string,
  zip?: string,
  district?: string
}
```

**Example Request:**
```bash
curl -X POST http://localhost:3000/signup \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John",
    "last_name": "Doe", 
    "email": "john.doe@example.com",
    "password": "SecurePassword123!",
    "terms_and_privacy_agreement": true
  }'
```

**Success Response (201):**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": 123,
      "email": "john.doe@example.com",
      "name": "John",
      "last_name": "Doe"
    },
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "rt_xxxxxxxxxxxxxxxxxxxxxxxx"
  },
  "message": "User created successfully"
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
  password: string,
  remember_user?: boolean
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
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "rt_xxxxxxxxxxxxxxxxxxxxxxxx",
    "user": {
      "id": 123,
      "email": "john.doe@example.com",
      "name": "John"
    }
  }
}
```

**MFA Required Response (200):**
```json
{
  "success": true,
  "data": {
    "mfa_required": true,
    "visitor_id": "visitor_xxxxxxxxxx"
  },
  "message": "MFA verification required. Check your email."
}
```

**Error Responses:**
- `400` - Invalid request format
- `401` - Invalid credentials
- `429` - Rate limit exceeded
- `423` - Account temporarily locked

### POST /auth/oauth/:provider

OAuth authentication with third-party providers.

**URL Parameters:**
- `provider` - OAuth provider name (e.g., "google", "github", "facebook")

**Request Body:**
```typescript
{
  code: string,           // OAuth authorization code
  state?: string,         // OAuth state parameter
  redirect_uri: string    // OAuth redirect URI
}
```

**Example Request:**
```bash
curl -X POST http://localhost:3000/auth/oauth/google \
  -H "Content-Type: application/json" \
  -d '{
    "code": "4/0AX4XfWjj...",
    "redirect_uri": "https://yourapp.com/auth/callback"
  }'
```

**Success Response (200):**
```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "rt_xxxxxxxxxxxxxxxxxxxxxxxx",
    "user": {
      "id": 123,
      "email": "john.doe@gmail.com",
      "name": "John",
      "provider": "google",
      "provider_id": "google_user_id"
    }
  }
}
```

**Error Responses:**
- `400` - Invalid OAuth code or parameters
- `401` - OAuth authentication failed
- `404` - Provider not supported
- `429` - Rate limit exceeded

## Token Management Routes

These routes are mounted under the `/token` prefix.

### POST /token/auth/refresh-access

Refresh an expired access token using a valid refresh token.

**Headers:**
```
Authorization: Bearer <refresh_token>
```

**Example Request:**
```bash
curl -X POST http://localhost:3000/token/auth/refresh-access \
  -H "Authorization: Bearer rt_xxxxxxxxxxxxxxxxxxxxxxxx"
```

**Success Response (200):**
```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 900
  }
}
```

**Error Responses:**
- `401` - Invalid or expired refresh token
- `403` - Token revoked or user deactivated
- `429` - Rate limit exceeded

### POST /token/auth/user/refresh-session

Rotate refresh token and issue new session tokens.

**Headers:**
```
Authorization: Bearer <refresh_token>
```

**Example Request:**
```bash
curl -X POST http://localhost:3000/token/auth/user/refresh-session \
  -H "Authorization: Bearer rt_xxxxxxxxxxxxxxxxxxxxxxxx"
```

**Success Response (200):**
```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "rt_yyyyyyyyyyyyyyyyyyyyyyyy",
    "expires_in": 900
  }
}
```

**Error Responses:**
- `401` - Invalid refresh token
- `403` - Maximum sessions exceeded
- `429` - Rate limit exceeded

### POST /token/auth/logout

Revoke the current refresh token and end the session.

**Headers:**
```
Authorization: Bearer <refresh_token>
```

**Example Request:**
```bash
curl -X POST http://localhost:3000/token/auth/logout \
  -H "Authorization: Bearer rt_xxxxxxxxxxxxxxxxxxxxxxxx"
```

**Success Response (200):**
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

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

Verify multi-factor authentication using magic link.

**URL Parameters:**
- `visitor` - MFA verification token

**Example Request:**
```bash
curl -X GET http://localhost:3000/auth/verify-mfa/mfa_xxxxxxxxxx
```

**Success Response (200):**
```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "rt_xxxxxxxxxxxxxxxxxxxxxxxx",
    "user": {
      "id": 123,
      "email": "john.doe@example.com"
    }
  },
  "message": "MFA verified successfully"
}
```

**Error Responses:**
- `401` - Invalid or expired MFA token
- `404` - MFA token not found
- `429` - Rate limit exceeded

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
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 4
X-RateLimit-Reset: 1640995200
```

### Rate Limit Exceeded Response

```json
{
  "success": false,
  "error": "RATE_LIMITED",
  "message": "Too many requests. Try again later.",
  "retry_after": 300
}
```

### Rate Limiting Scopes

Different endpoints have different rate limiting scopes:

| Endpoint | Scope | Limit |
|----------|-------|-------|
| `/login` | IP + Email | 5/min, 15/15min |
| `/signup` | IP + Email | 3/hour, 10/day |
| `/auth/oauth/*` | IP + Provider | 5/min, 15/15min |
| `/token/auth/*` | User + IP | 10/5min, 50/hour |
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
curl -X POST http://localhost:3000/token/auth/refresh-access \
  -H "Authorization: Bearer rt_xxxxxxxxxxxxxxxxxxxxxxxx"

# 4. Logout
curl -X POST http://localhost:3000/token/auth/logout \
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
1. **Parse error responses** - Always check the `success` field
2. **Handle rate limiting** - Respect `retry_after` values
3. **Implement fallbacks** - Graceful degradation for auth failures
4. **Log security events** - Monitor for unusual authentication patterns

### Security
1. **Validate all inputs** - Don't trust client-side validation
2. **Implement CSRF protection** - Use proper CSRF tokens
3. **Monitor for abuse** - Watch for unusual patterns
4. **Keep tokens short-lived** - Regular token rotation