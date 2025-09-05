import { describe, test, expect, vi } from 'vitest';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';

import { generateAccessToken, verifyAccessToken, AccessTokenPayload } from '../../src/accessTokens.js';
import { tokenCache } from '../../src/jwtAuth/utils/accessTokentCache.js';
import { getConfiguration } from '../../src/jwtAuth/config/configuration.js';
import './setup.js';

describe('Advanced Edge Cases and Stress Testing', () => {
  test('should handle massive concurrent verification stress test', async () => {
    const concurrency = 100;
    const users = Array.from({ length: concurrency }, (_, i) => ({
      id: i,
      visitor_id: i * 100,
      jti: crypto.randomUUID()
    }));

    // Generate all tokens first
    const tokens = users.map(user => generateAccessToken(user));

    // Create multiple verification rounds
    const rounds = 5;
    const allPromises: Promise<any>[] = [];

    for (let round = 0; round < rounds; round++) {
      const roundPromises = tokens.map(async (token, index) => {
        // Add some randomness to create race conditions
        await new Promise(resolve => setTimeout(resolve, Math.random() * 10));
        return verifyAccessToken(token);
      });
      allPromises.push(...roundPromises);
    }

    const results = await Promise.all(allPromises);

    // All verifications should succeed
    expect(results).toHaveLength(concurrency * rounds);
    results.forEach(result => {
      expect(result.valid).toBe(true);
    });
  });

  test('should handle cache thrashing with rapid add/remove cycles', () => {
    const cache = tokenCache();
    const originalSize = cache.size;
    
    // Rapid generation and invalidation cycles
    for (let cycle = 0; cycle < 10; cycle++) {
      const tokens: string[] = [];
      
      // Generate many tokens rapidly
      for (let i = 0; i < 20; i++) {
        const user: AccessTokenPayload = {
          id: cycle * 20 + i,
          visitor_id: (cycle * 20 + i) * 100,
          jti: crypto.randomUUID()
        };
        const token = generateAccessToken(user);
        tokens.push(token);
      }
      
      // Verify all tokens
      tokens.forEach(token => {
        const result = verifyAccessToken(token);
        expect(result.valid).toBe(true);
      });
      
      // Manually invalidate some tokens
      tokens.slice(0, 10).forEach(token => {
        const cacheEntry = cache.get(token);
        if (cacheEntry) {
          cache.set(token, { ...cacheEntry, valid: false });
        }
      });
      
      // Verify invalidated tokens are rejected
      tokens.slice(0, 10).forEach(token => {
        const result = verifyAccessToken(token);
        expect(result.valid).toBe(false);
        expect(result.errorType).toBe('InvalidPayloadType');
      });
    }
  });

  test('should handle mixed valid and invalid tokens in batch verification', async () => {
    const validUsers = Array.from({ length: 25 }, (_, i) => ({
      id: i,
      visitor_id: i * 100,
      jti: crypto.randomUUID()
    }));

    const config = getConfiguration();
    
    // Generate valid tokens
    const validTokens = validUsers.map(user => generateAccessToken(user));
    
    // Create invalid tokens (not in cache)
    const invalidTokens = Array.from({ length: 25 }, (_, i) => {
      const payload = {
        visitor: i * 100,
        roles: []
      };
      return jwt.sign(payload, config.jwt.jwt_secret_key, {
        algorithm: 'HS512',
        expiresIn: '15m',
        audience: 'example.com',
        issuer: 'example.com',
        subject: i.toString(),
        jwtid: crypto.randomUUID()
      });
    });

    // Mix valid and invalid tokens
    const allTokens = [...validTokens, ...invalidTokens].sort(() => Math.random() - 0.5);

    // Verify all tokens concurrently
    const results = await Promise.all(
      allTokens.map(token => Promise.resolve(verifyAccessToken(token)))
    );

    // Count valid and invalid results
    const validResults = results.filter(r => r.valid);
    const invalidResults = results.filter(r => !r.valid);

    expect(validResults).toHaveLength(25);
    expect(invalidResults).toHaveLength(25);
    invalidResults.forEach(result => {
      expect(result.errorType).toBe('InvalidPayloadType');
    });
  });

  test('should handle token verification with extreme role combinations', () => {
    const extremeRoleCombinations = [
      [], // No roles
      ['a'], // Single character role
      ['role-with-many-special-chars!@#$%^&*()'], // Special characters
      ['UPPERCASE', 'lowercase', 'MiXeDcAsE'], // Case variations
      ['role with spaces'], // Spaces in roles
      ['role\nwith\nnewlines'], // Newlines
      ['role\twith\ttabs'], // Tabs
      ['role"with"quotes'], // Quotes
      ['role\\with\\backslashes'], // Backslashes
      ['role/with/slashes'], // Forward slashes
      ['role.with.dots'], // Dots
      ['role,with,commas'], // Commas
      ['role;with;semicolons'], // Semicolons
      ['role:with:colons'], // Colons
      ['🚀', '🎉', '💻'], // Emoji roles
      ['عربي', '中文', 'हिंदी'], // Unicode roles
      Array.from({ length: 100 }, (_, i) => `role${i}`) // Many roles
    ];

    extremeRoleCombinations.forEach((roles, index) => {
      const user: AccessTokenPayload = {
        id: index,
        visitor_id: index * 100,
        jti: crypto.randomUUID(),
        role: roles
      };

      const token = generateAccessToken(user);
      const result = verifyAccessToken(token);

      expect(result.valid).toBe(true);
      expect(result.payload?.roles).toEqual(roles);
    });
  });

  test('should handle boundary value testing for numeric fields', () => {
    const boundaryValues = [
      { id: 0, visitor_id: 0 },
      { id: 1, visitor_id: 1 },
      { id: -1, visitor_id: -1 },
      { id: Number.MAX_SAFE_INTEGER, visitor_id: Number.MAX_SAFE_INTEGER },
      { id: Number.MIN_SAFE_INTEGER, visitor_id: Number.MIN_SAFE_INTEGER },
      { id: 2147483647, visitor_id: 2147483647 }, // 32-bit max
      { id: -2147483648, visitor_id: -2147483648 }, // 32-bit min
      { id: 1.5, visitor_id: 2.7 }, // Floating point
    ];

    boundaryValues.forEach((values, index) => {
      const user: any = {
        ...values,
        jti: crypto.randomUUID()
      };

      const token = generateAccessToken(user);
      const result = verifyAccessToken(token);

      expect(result.valid).toBe(true);
      expect(result.payload?.sub).toBe(values.id.toString());
      expect(result.payload?.visitor).toBe(values.visitor_id);
    });
  });

  test('should handle cache poisoning resistance', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const config = getConfiguration();
    const cache = tokenCache();
    
    // Generate legitimate token
    const legitimateToken = generateAccessToken(user);
    
    // Attempt to poison cache with malicious entries
    const maliciousEntries = [
      'malicious-token-1',
      'malicious-token-2',
      'totally-fake-jwt'
    ];

    maliciousEntries.forEach(maliciousToken => {
      // Try to add malicious token to cache manually
      cache.set(maliciousToken, {
        jti: 'fake-jti',
        visitorId: 999,
        userId: 999,
        roles: ['admin', 'superuser'],
        valid: true
      });
    });

    // Verify malicious tokens are rejected (cache-first design prevents this)
    maliciousEntries.forEach(maliciousToken => {
      const result = verifyAccessToken(maliciousToken);
      // These should fail at JWT verification level since they're not valid JWTs
      expect(result.valid).toBe(false);
      expect(['jwt malformed', 'invalid token', 'JsonWebTokenError']).toContain(result.errorType);
    });

    // Verify legitimate token still works
    const legitimateResult = verifyAccessToken(legitimateToken);
    expect(legitimateResult.valid).toBe(true);
  });

  test('should handle memory pressure with large payloads', () => {
    const users: AccessTokenPayload[] = [];
    const tokens: string[] = [];

    // Generate tokens with progressively larger payloads
    for (let i = 0; i < 50; i++) {
      const user: AccessTokenPayload = {
        id: i,
        visitor_id: i * 100,
        jti: crypto.randomUUID(),
        role: Array.from({ length: i * 10 }, (_, j) => `role${i}-${j}`)
      };
      users.push(user);
      
      const token = generateAccessToken(user);
      tokens.push(token);
    }

    // Verify all tokens work despite large payloads
    tokens.forEach((token, index) => {
      const result = verifyAccessToken(token);
      expect(result.valid).toBe(true);
      expect(result.payload?.roles).toHaveLength(index * 10);
    });
  });

  test('should handle time-based race conditions', async () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    // Generate token
    const token = generateAccessToken(user);
    
    // Create multiple concurrent operations that might cause race conditions
    const operations = [
      () => verifyAccessToken(token),
      () => verifyAccessToken(token),
      () => {
        const cache = tokenCache();
        const entry = cache.get(token);
        if (entry) {
          cache.set(token, { ...entry, valid: false });
        }
      },
      () => verifyAccessToken(token),
      () => {
        const cache = tokenCache();
        cache.delete(token);
      },
      () => verifyAccessToken(token),
    ];

    // Execute operations concurrently
    const results = await Promise.allSettled(
      operations.map(op => Promise.resolve(op()))
    );

    // At least some operations should complete successfully
    const fulfilled = results.filter(r => r.status === 'fulfilled');
    expect(fulfilled.length).toBeGreaterThan(0);
  });

  test('should handle JWT with unusual but valid structures', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const config = getConfiguration();
    
    // Create JWT with minimal payload
    const minimalPayload = {
      visitor: user.visitor_id,
      roles: []
    };

    const minimalToken = jwt.sign(minimalPayload, config.jwt.jwt_secret_key, {
      algorithm: 'HS512',
      expiresIn: '15m',
      audience: 'example.com',
      issuer: 'example.com',
      subject: user.id.toString(),
      jwtid: user.jti
    });

    // Add to cache
    const cache = tokenCache();
    cache.set(minimalToken, {
      jti: user.jti,
      visitorId: user.visitor_id,
      userId: user.id,
      roles: [],
      valid: true
    });

    const result = verifyAccessToken(minimalToken);
    expect(result.valid).toBe(true);
  });

  test('should handle rapid token invalidation and re-validation cycles', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const token = generateAccessToken(user);
    const cache = tokenCache();

    // Perform rapid invalidation/validation cycles
    for (let i = 0; i < 100; i++) {
      // Invalidate
      const entry = cache.get(token);
      if (entry) {
        cache.set(token, { ...entry, valid: false });
      }
      
      let result = verifyAccessToken(token);
      expect(result.valid).toBe(false);
      
      // Re-validate
      if (entry) {
        cache.set(token, { ...entry, valid: true });
      }
      
      result = verifyAccessToken(token);
      expect(result.valid).toBe(true);
    }
  });
});