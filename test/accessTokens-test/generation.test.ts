import { describe, test, expect } from 'vitest';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';

import { generateAccessToken, AccessTokenPayload } from '../../src/accessTokens.js';
import { getConfiguration } from '../../src/jwtAuth/config/configuration.js';

describe('generateAccessToken', () => {
  test('should generate a valid JWT access token with required claims', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
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
  });

  test('should generate token with custom roles', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID(),
      role: ['admin', 'user']
    };

    const token = generateAccessToken(user);
    const decoded = jwt.decode(token) as any;

    expect(decoded.roles).toEqual(['admin', 'user']);
  });

  test('should handle empty roles array', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID(),
      role: []
    };

    const token = generateAccessToken(user);
    const decoded = jwt.decode(token) as any;

    expect(decoded.roles).toEqual([]);
  });

  test('should generate unique tokens for same user data', () => {
    const user1: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };
    
    const user2: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID() 
    };

    const token1 = generateAccessToken(user1);
    const token2 = generateAccessToken(user2);

    expect(token1).not.toBe(token2);
  });

  test('should handle edge case user IDs', () => {
    const users = [
      { id: 0, visitor_id: 0, jti: crypto.randomUUID() },
      { id: 2147483647, visitor_id: 2147483647, jti: crypto.randomUUID() }, 
      { id: 1, visitor_id: 999999999, jti: crypto.randomUUID() }
    ];

    users.forEach(user => {
      const token = generateAccessToken(user);
      const decoded = jwt.decode(token) as any;
      expect(decoded.sub).toBe(user.id.toString());
      expect(decoded.visitor).toBe(user.visitor_id);
    });
  });
});