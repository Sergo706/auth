import { describe, test, expect, vi } from 'vitest';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import * as configuration from '../../src/jwtAuth/config/configuration.js';
import { generateAccessToken, verifyAccessToken, AccessTokenPayload } from '../../src/accessTokens.js';
import { tokenCache, TokenCacheEntry } from '../../src/jwtAuth/utils/accessTokentCache.js';

describe('Security Tests', () => {
  test('should reject JWT none algorithm attack', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    generateAccessToken(user);

    const unsignedPayload = {
      visitor: user.visitor_id,
      roles: [],
      sub: user.id.toString(),
      jti: user.jti,
      aud: 'example.com',
      iss: 'example.com'
    };

    const header = { alg: 'none', typ: 'JWT' };
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
    const encodedPayload = Buffer.from(JSON.stringify(unsignedPayload)).toString('base64url');
    const noneToken = `${encodedHeader}.${encodedPayload}.`;

    const result = verifyAccessToken(noneToken);

    expect(result.valid).toBe(false);
    expect(['invalid signature', 'jwt malformed', 'JsonWebTokenError', 'InvalidPayloadType']).toContain(result.errorType);
  });

  test('rejects JWT "none" algorithm via cache-first short-circuit', () => {
    const user: AccessTokenPayload = { id: 123, visitor_id: 456, jti: crypto.randomUUID() };
    const legit = generateAccessToken(user);
    expect(verifyAccessToken(legit).valid).toBe(true);

    const verifySpy = vi.spyOn(jwt, 'verify');
    try {
      const header = { alg: 'none', typ: 'JWT' };
      const payload = {
        visitor: user.visitor_id,
        roles: [],
        sub: String(user.id),
        jti: user.jti,
        aud: 'example.com',
        iss: 'example.com',
      };

      const noneToken = [
        Buffer.from(JSON.stringify(header)).toString('base64url'),
        Buffer.from(JSON.stringify(payload)).toString('base64url'),
        '', // no signature
      ].join('.');

      const result = verifyAccessToken(noneToken);

      expect(result).toEqual({ valid: false, errorType: 'InvalidPayloadType' });
      expect(verifySpy).not.toHaveBeenCalled();
    } finally {
      verifySpy.mockRestore();
    }
  });


    test('rejects token signed with different algorithm via cache-first', () => {
    const user: AccessTokenPayload = { id: 123, visitor_id: 456, jti: crypto.randomUUID() };
    generateAccessToken(user); 

    const verifySpy = vi.spyOn(jwt, 'verify');
    try {
      const crafted = jwt.sign(
        { visitor: user.visitor_id, roles: [] },
        'test-jwt-secret-key-32-chars-long',
        {
          algorithm: 'HS256', 
          expiresIn: '15m',
          subject: String(user.id),
          jwtid: user.jti,
          audience: 'example.com',
          issuer: 'example.com',
        }
      );

      const result = verifyAccessToken(crafted);

      expect(result).toEqual({ valid: false, errorType: 'InvalidPayloadType' });
      expect(verifySpy).not.toHaveBeenCalled();
    } finally {
      verifySpy.mockRestore();
    }
  });

  test('algorithm mismatch AFTER cache hit triggers signature/alg error', () => {
    const user: AccessTokenPayload = { id: 1, visitor_id: 2, jti: crypto.randomUUID(), role: ['user'] };
    const token = generateAccessToken(user); 

    expect(verifyAccessToken(token).valid).toBe(true);

    const realGet = configuration.getConfiguration;
    const cfgSpy = vi.spyOn(configuration, 'getConfiguration').mockImplementation(() => {
      const cfg = realGet();
      return {
        ...cfg,
        jwt: {
          ...cfg.jwt,
          access_tokens: {
            ...cfg.jwt.access_tokens,
            algorithm: 'HS256', 
          },
        },
      };
    });

    try {
      const result = verifyAccessToken(token);
      expect(result.valid).toBe(false);
      expect(['invalid signature', 'JsonWebTokenError']).toContain(result.errorType);
    } finally {
      cfgSpy.mockRestore();
    }
  });

  test('handles large payloads and remains valid', () => {
    const largeRole = 'x'.repeat(1000); // ~1KB role
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID(),
      role: [largeRole],
    };

    const token = generateAccessToken(user);
    const result = verifyAccessToken(token);

    expect(result.valid).toBe(true);
    expect(result.payload?.roles).toEqual([largeRole]);
  });

  test('should handle special characters in JTI', () => {
    const specialJtis = [
      'test-jti-with-hyphens',
      'test_jti_with_underscores',
      'testjti123456789',
      crypto.randomUUID()
    ];

    specialJtis.forEach(jti => {
      const user: AccessTokenPayload = {
        id: 123,
        visitor_id: 456,
        jti
      };

      const token = generateAccessToken(user);
      const result = verifyAccessToken(token);

      expect(result.valid).toBe(true);
      expect(result.payload?.jti).toBe(jti);
    });
  });

   test('roles: extras in payload vs required should report InvalidRoles (payload has extra)', () => {
    const user: AccessTokenPayload = { id: 7, visitor_id: 8, jti: crypto.randomUUID(), role: ['reader', 'admin'] };
    const token = generateAccessToken(user);

    const cache = tokenCache();
    const entry = cache.get(token);
    expect(entry).toBeTruthy();
    
   cache.set(token, {
  ...(entry as TokenCacheEntry), 
  roles: ['reader'],
   });

    const result = verifyAccessToken(token);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('InvalidRoles');
  });

  test('roles: missing roles vs required should report InvalidRoles (payload missing required)', () => {
    const user: AccessTokenPayload = { id: 9, visitor_id: 10, jti: crypto.randomUUID(), role: ['reader'] };
    const token = generateAccessToken(user);

    const cache = tokenCache();
    const entry = cache.get(token);
    expect(entry).toBeTruthy();

       cache.set(token, {
      ...(entry as TokenCacheEntry), 
      roles: ['reader', 'admin'],
      });

    const result = verifyAccessToken(token);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('InvalidRoles');
  });

  test('roles: malformed types are rejected (cache roles not all strings)', () => {
    const user: AccessTokenPayload = { id: 11, visitor_id: 12, jti: crypto.randomUUID(), role: ['reader'] };
    const token = generateAccessToken(user);

    const cache = tokenCache();
    const entry = cache.get(token);
    expect(entry).toBeTruthy();
    cache.set(token, { ...(entry as TokenCacheEntry), roles: ['reader', 123 as any] });

    const result = verifyAccessToken(token);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('MalformedPayload');
  });

  test('visitor mismatch is rejected', () => {
    const user: AccessTokenPayload = { id: 21, visitor_id: 22, jti: crypto.randomUUID(), role: ['user'] };
    const token = generateAccessToken(user);

    const cache = tokenCache();
    const entry = cache.get(token);
    expect(entry).toBeTruthy();
    cache.set(token, { ...(entry as TokenCacheEntry), visitorId: 999 });

    const result = verifyAccessToken(token);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('Invalid visitor id');
  });
  
});