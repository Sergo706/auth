import { generateAccessToken, AccessTokenPayload } from '../../../src/accessTokens.js';
import { tokenCache } from '../../../src/jwtAuth/utils/accessTokentCache.js';
import { describe, expect, it } from "vitest";
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { getConfiguration } from '~~/config/configuration.js';

describe('access tokens main', () => {
    it('should generate a valid JWT access token with required claims', () => {
        const user: AccessTokenPayload = {
        id: 123,
        visitor_id: 'test',
        jti: crypto.randomUUID()
        };

        const config = getConfiguration();
        const token = generateAccessToken(user);

       expect(token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);

        const decoded = jwt.decode(token, { complete: true }) as any;
        expect(decoded).toBeTruthy();
        expect(decoded.payload.visitor).toBe(user.visitor_id);
        expect(decoded.payload.sub).toBe(user.id.toString());
        expect(decoded.payload.jti).toBe(user.jti);
        expect(decoded.payload.roles).toEqual([]);
        expect(decoded.payload.aud).toBe(config.jwt.access_tokens.audience ?? config.jwt.refresh_tokens.domain);
        expect(decoded.payload.iss).toBe(config.jwt.access_tokens.audience ?? config.jwt.refresh_tokens.domain);
    })

    it('should generate token with custom roles', () => {
        const user: AccessTokenPayload = {
            id: 123,
            visitor_id: "test",
            jti: crypto.randomUUID(),
            role: ['admin', 'user']
        };

        const token = generateAccessToken(user);
        const decoded = jwt.decode(token) as any;
        expect(decoded).toBeTruthy()
        expect(decoded.roles).toEqual(['admin', 'user']);
  });

   it('should handle empty roles array', () => {
        const user: AccessTokenPayload = {
        id: 123,
        visitor_id: "test",
        jti: crypto.randomUUID(),
        role: []
        };

        const token = generateAccessToken(user);
        const decoded = jwt.decode(token) as any;
        expect(decoded).toBeTruthy()
        expect(decoded.roles).toEqual([]);
  });

  it('should generate unique tokens for same user data', () => {
        const user1: AccessTokenPayload = {
            id: 123,
            visitor_id: "456",
            jti: crypto.randomUUID()
        };
        
        const user2: AccessTokenPayload = {
            id: 123,
            visitor_id: "456",
            jti: crypto.randomUUID() 
        };

        const token1 = generateAccessToken(user1);
        const token2 = generateAccessToken(user2);

        expect(token1).not.toBe(token2);
  });

  it('should handle edge case user IDs', () => {
    const users = [
      { id: 0, visitor_id: "0", jti: crypto.randomUUID() },
      { id: 2147483647, visitor_id: "2147483647", jti: crypto.randomUUID() }, 
      { id: 1, visitor_id: "999999999", jti: crypto.randomUUID() }
    ];

    users.forEach(user => {
      const token = generateAccessToken(user);
      const decoded = jwt.decode(token) as any;
      expect(decoded.sub).toBe(user.id.toString());
      expect(decoded.visitor).toBe(user.visitor_id);
    });
  });

  it('should set token in tokenCache', () => {
    const user: AccessTokenPayload = {
        id: 123,
        visitor_id: "test",
        jti: crypto.randomUUID(),
        role: ['admin']
    };
    const token = generateAccessToken(user);
    const cache = tokenCache().get(token)
    expect(cache?.jti).toBe(user.jti)
    expect(cache?.visitorId).toBe(user.visitor_id)
    expect(cache?.userId).toBe(user.id)
    expect(cache?.roles).toContain(user.role?.[0]);
    expect(cache?.valid).toBe(true)
  })

})