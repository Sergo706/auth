import { describe, test, expect } from 'vitest';
import crypto from 'node:crypto';

import { generateAccessToken, verifyAccessToken, AccessTokenPayload } from '../../src/accessTokens.js';
import { tokenCache } from '../../src/jwtAuth/utils/accessTokentCache.js';


describe('Edge Cases and Error Handling', () => {
  test('should handle concurrent token generation', async () => {
    const users = Array.from({ length: 10 }, (_, i) => ({
      id: i,
      visitor_id: i * 100,
      jti: crypto.randomUUID()
    }));

    const promises = users.map(user => 
      Promise.resolve(generateAccessToken(user))
    );

    const tokens = await Promise.all(promises);

    const uniqueTokens = new Set(tokens);
    expect(uniqueTokens.size).toBe(tokens.length);

    tokens.forEach(token => {
      const result = verifyAccessToken(token);
      expect(result.valid).toBe(true);
    });
  });

  test('should handle very long role names', () => {
    const longRole = 'a'.repeat(500);
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID(),
      role: [longRole]
    };

    const token = generateAccessToken(user);
    const result = verifyAccessToken(token);

    expect(result.valid).toBe(true);
    expect(result.payload?.roles).toContain(longRole);
  });

  test('should handle many roles', () => {
    const manyRoles = Array.from({ length: 50 }, (_, i) => `role${i}`);
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID(),
      role: manyRoles
    };

    const token = generateAccessToken(user);
    const result = verifyAccessToken(token);

    expect(result.valid).toBe(true);
    expect(result.payload?.roles).toEqual(manyRoles);
  });

  test('should handle numeric and special character roles', () => {
    const specialRoles = ['123', 'role-with-dash', 'role_with_underscore', 'UPPERCASE', 'MixedCase'];
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID(),
      role: specialRoles
    };

    const token = generateAccessToken(user);
    const result = verifyAccessToken(token);

    expect(result.valid).toBe(true);
    expect(result.payload?.roles).toEqual(specialRoles);
  });

  test('should handle cache invalidation on verification failure', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const token = generateAccessToken(user);
    
    let result = verifyAccessToken(token);
    expect(result.valid).toBe(true);

    const cache = tokenCache();
    const cacheEntry = cache.get(token);
    if (cacheEntry) {
      cache.set(token, { ...cacheEntry, valid: false });
    }

    result = verifyAccessToken(token);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('InvalidPayloadType');
  });

  test('should handle empty string tokens gracefully', () => {
    const result = verifyAccessToken('');
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('InvalidPayloadType');
  });

  test('should handle null-like tokens gracefully', () => {
    const invalidTokens = ['null', 'undefined', '{}', 'false'];
    
    invalidTokens.forEach(token => {
      const result = verifyAccessToken(token);
      expect(result.valid).toBe(false);
      expect(result.errorType).toBe('InvalidPayloadType');
    });
  });

  test('should verify cache TTL behavior exists', () => {
    const cache = tokenCache();
    expect(cache.max).toBeGreaterThan(0);
    expect(cache.ttl).toBeGreaterThan(0);
  });

  test('should handle unicode characters in roles', () => {
    const unicodeRoles = ['admin', 'user', '管理员', 'rôle-spécial', '🚀-emoji-role'];
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID(),
      role: unicodeRoles
    };

    const token = generateAccessToken(user);
    const result = verifyAccessToken(token);

    expect(result.valid).toBe(true);
    expect(result.payload?.roles).toEqual(unicodeRoles);
  });
});