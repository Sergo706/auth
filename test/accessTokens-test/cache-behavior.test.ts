import { describe, test, expect, vi } from 'vitest';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';

import { generateAccessToken, verifyAccessToken, AccessTokenPayload } from '../../src/accessTokens.js';
import { tokenCache } from '../../src/jwtAuth/utils/accessTokentCache.js';
import { getConfiguration } from '../../src/jwtAuth/config/configuration.js';


describe('Cache Behavior and Expiration', () => {
  test('should handle token expiration with cache cleanup', async () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const config = getConfiguration();
    
    const payload = {
      visitor: user.visitor_id,
      roles: []
    };
    const expiredToken = jwt.sign(payload, config.jwt.jwt_secret_key, {
      algorithm: 'HS512',
      expiresIn: '-1s', 
      audience: 'example.com',
      issuer: 'example.com',
      subject: user.id.toString(),
      jwtid: user.jti
    });

    const cache = tokenCache();
    cache.set(expiredToken, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    });

    expect(cache.has(expiredToken)).toBe(true);

    const result = verifyAccessToken(expiredToken);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('TokenExpiredError');

    expect(cache.has(expiredToken)).toBe(false);
  });

  test('should handle cache capacity pressure and eviction', () => {
    const cache = tokenCache();
    const originalMax = cache.max;
    
    const tokens: string[] = [];
    const users: AccessTokenPayload[] = [];
    
    for (let i = 0; i < originalMax + 10; i++) {
      const user: AccessTokenPayload = {
        id: i,
        visitor_id: i * 100,
        jti: crypto.randomUUID()
      };
      users.push(user);
      const token = generateAccessToken(user);
      tokens.push(token);
    }

    expect(cache.size).toBeLessThanOrEqual(originalMax);

    let evictedCount = 0;
    for (let i = 0; i < Math.min(10, tokens.length); i++) {
      if (!cache.has(tokens[i])) {
        evictedCount++;
      }
    }

    if (tokens.length > originalMax) {
      expect(evictedCount).toBeGreaterThan(0);
    }

    const recentTokens = tokens.slice(-5);
    recentTokens.forEach(token => {
      expect(cache.has(token)).toBe(true);
    });
  });

  test('should handle concurrent verification operations', async () => {
    const users = Array.from({ length: 20 }, (_, i) => ({
      id: i,
      visitor_id: i * 100,
      jti: crypto.randomUUID()
    }));

    const tokens = users.map(user => generateAccessToken(user));

    const verificationPromises = tokens.map(token => 
      Promise.resolve(verifyAccessToken(token))
    );

    const results = await Promise.all(verificationPromises);

    results.forEach((result, index) => {
      expect(result.valid).toBe(true);
      expect(result.payload?.visitor).toBe(users[index].visitor_id);
    });
  });

  test('should handle cache TTL configuration', () => {
    const cache = tokenCache();
    
    expect(cache.ttl).toBeGreaterThan(0);
    expect(cache.max).toBeGreaterThan(0);

    expect(cache.ttl).toBeLessThan(24 * 60 * 60 * 1000); 
    expect(cache.ttl).toBeGreaterThan(1000); 
  });

  test('should handle rapid token generation and verification cycles', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    // Rapidly generate and verify many tokens
    for (let i = 0; i < 100; i++) {
      const userWithUniqueJti = { ...user, jti: crypto.randomUUID() };
      const token = generateAccessToken(userWithUniqueJti);
      const result = verifyAccessToken(token);
      
      expect(result.valid).toBe(true);
      expect(result.payload?.visitor).toBe(user.visitor_id);
    }
  });

  test('should handle cache state corruption gracefully', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const token = generateAccessToken(user);
    const cache = tokenCache();
    
    let result = verifyAccessToken(token);
    expect(result.valid).toBe(true);

    cache.set(token, null as any);

    result = verifyAccessToken(token);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('InvalidPayloadType');
  });

  test('should handle cache with incomplete data', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const config = getConfiguration();
    const cache = tokenCache();
    
    const payload = {
      visitor: user.visitor_id,
      roles: []
    };
    const token = jwt.sign(payload, config.jwt.jwt_secret_key, {
      algorithm: 'HS512',
      expiresIn: '15m',
      audience: 'example.com',
      issuer: 'example.com',
      subject: user.id.toString(),
      jwtid: user.jti
    });

    cache.set(token, { 
      jti: user.jti,
      // Missing visitorId, userId, roles, valid
    } as any);

    const result = verifyAccessToken(token);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('InvalidPayloadType');
  });

  test('should handle cache entry with wrong data types', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const config = getConfiguration();
    const cache = tokenCache();
    
    const payload = {
      visitor: user.visitor_id,
      roles: []
    };
    const token = jwt.sign(payload, config.jwt.jwt_secret_key, {
      algorithm: 'HS512',
      expiresIn: '15m',
      audience: 'example.com',
      issuer: 'example.com',
      subject: user.id.toString(),
      jwtid: user.jti
    });

    cache.set(token, { 
      jti: user.jti,
      visitorId: 'not-a-number', 
      userId: user.id,
      roles: 'not-an-array', 
      valid: 'not-a-boolean'
    } as any);

    const result = verifyAccessToken(token);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('InvalidPayloadType');
  });
});