# JWT Auth Library

This project provides a collection of Express middleware and utilities for building an authentication system using JSON Web Tokens (JWTs). It ships as a TypeScript library and exposes routes and helpers for common tasks such as sign up, login, OAuth flows, magic links and token rotation.

## Project structure

```
src/
  accessTokens.ts         - Access token generation and verification
  refreshTokens.ts        - Refresh token issuance and rotation helpers
  tempLinks.ts            - Temporary JWT links (MFA & password reset)
  anomalies.ts            - Heuristics for detecting suspicious activity
  main.ts                 - Re-exports routes and middleware
  jwtAuth/
    config/               - Library configuration and DB connection utilities
    controllers/          - Route handlers for login, logout, OAuth, etc.
    middleware/           - Express middleware used by the routes
    models/               - Database helpers for user management
    routes/               - Express routers bundled with the library
    types/                - Shared TypeScript types
    utils/                - Helper utilities (rate limiters, hashing, email, ...)
```

The compiled JavaScript is emitted to `dist/` when running the build script.

## Usage

Install the dependencies and build the project:

```bash
npm install
npm run build
```

In your application, configure the library once at startup and mount the provided routes:

```ts
import express from 'express';
import { configuration, authenticationRoutes, magicLinks, tokenRotationRoutes } from '@riavzon/jwtauth';

const app = express();

configuration({
  store: {/* database pools */},
  telegram: {/* bot config */},
  jwt: {/* secrets and token options */},
  email: {/* SMTP/resend config */},
  password: {/* password policy */},
  logLevel: 'info',
  magic_links: {/* magic link config */}
});

app.use(authenticationRoutes);
app.use(magicLinks);
app.use('/token', tokenRotationRoutes);
```

Refer to the TypeScript declarations under `src/` for detailed type information about each function.

## Deployment architecture

This library is meant to run on an API server that acts as the single source of
truth for authentication. Other services (for example a BFF server used by your
frontend) forward requests to this API server when authentication or
authorization is required. A typical flow is:

1. The client or BFF submits credentials to the API server.
2. The API server verifies the credentials using this library and issues JWT
   access and refresh tokens.
3. Access tokens are then presented back to the API server for protected
   endpoints or passed to other internal services via the API server.
4. A database or other protected service is never contacted directly by the
   client. It only receives requests from the API server once the JWT has been
   validated.

Multiple API instances can share the same configuration by pointing them at the
same database. Token verification and rate limiting stay consistent across the
cluster.

## Available routes

The following endpoints are exposed when you mount the provided routers:

- `POST /signup` – create a new user
- `POST /login` – obtain tokens with email and password
- `POST /auth/oauth/:provider` – login through a third‑party provider
- `GET /auth/verify-mfa/:visitor` – verify multi‑factor links
- `POST /auth/forgot-password` – initiate the password reset flow
- `POST /auth/reset-password/:visitor` – verify and update passwords
- `POST /token/auth/refresh-access` – rotate an access token
- `POST /token/auth/user/refresh-session` – rotate and issue new refresh tokens
- `POST /token/auth/logout` – revoke the current refresh token

## Token rotation and magic links

Refresh tokens are hashed and stored in your database. The library can rotate
them automatically on every use or only when they are near expiry. Temporary
magic links are short‑lived JWTs that allow one‑time actions such as verifying
MFA or resetting a password. Helper functions are provided for generating and
verifying these links.

## Configuration

Call `configuration({...})` once at startup. Important options include:

- `store`: database connection pools
- `jwt`: secrets and signing options
- `email`: SMTP or Resend configuration
- `magic_links`: lifetime and issuer settings for temporary links
- `password`: password policy and hashing parameters

See `src/jwtAuth/types/config.ts` for the complete schema.

## Example multi-instance setup

Imagine three services:

- **API Server** – Runs this library and holds the database connections.
- **BFF Server** – A gateway for the frontend that never talks to the database
  directly. It forwards authentication requests to the API server.
- **Database Server** – Completely isolated. Only the API server communicates
  with it.

1. The user logs in through the BFF, which forwards the request to the API
   server's `/login` route.
2. The API server validates the credentials and returns access and refresh
   tokens.
3. Subsequent requests from the frontend include the access token. The BFF
   passes these to the API server.
4. The API server verifies the token and, if authorized, queries the database
   and returns the result to the BFF.

This keeps all authentication logic centralized while allowing your frontend and
API layers to scale independently.

## Building

Run `npm run build` to compile the TypeScript source into `dist/`. The command
also copies the email templates and other assets.

---

Low‑level documentation is available in the TypeScript declarations and JSDoc
comments throughout the code base.

