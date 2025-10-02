# Service vs Library Usage

This repository can be used in two ways: as an embedded library in your Express application, or as a standalone service.

## Library Usage

- Import and mount the provided routers and middleware directly in your Express app.
- Control routing prefixes (e.g., mount `tokenRotationRoutes` at `/token` if desired).
- Add cross-cutting concerns such as CSRF protection, UI, and app-specific authorization.
- Typical mounting:

```
app.use(authenticationRoutes);  // /signup, /login, /auth/OAuth/:providerName
app.use(magicLinks);            // /auth/verify-mfa/:visitor, /auth/reset-password/:visitor
app.use(tokenRotationRoutes);   // /auth/refresh-access, /auth/logout, etc.
```

## Service Usage

- Run the pre-wired Express service in `src/service.ts` (e.g., via Docker).
- Configure via JSON (see CONFIGURATION.md); secure defaults are applied.
- Exposes the same routes as the library, without UI.
- Does not include CSRF protection or a full browser-based OAuth flow; these should be implemented by the client or gateway.

## Client Library (Recommended)

For front-end applications or BFFs interacting with the service:

- Implement CSRF protection tailored to your app.
- Handle full OAuth flows (browser redirects, state, and PKCE if applicable).
- Manage refresh/access token lifecycles and retries per your UX needs.

This separation keeps the service focused on authentication primitives (validation, token lifecycle, rate limiting, bot detection), while the client handles presentation and app-specific protections.

