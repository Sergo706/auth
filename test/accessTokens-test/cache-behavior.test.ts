import { describe, test, expect, vi } from 'vitest';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';

import { generateAccessToken, verifyAccessToken, AccessTokenPayload } from '../../src/accessTokens.js';
import { tokenCache } from '../../src/jwtAuth/utils/accessTokentCache.js';
import { getConfiguration } from '../../src/jwtAuth/config/configuration.js';
import './setup.js';

describe('Cache Behavior and Expiration', () => {
  test('should handle token expiration with cache cleanup', async () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const config = getConfiguration();
    
    // Create an expired token manually
    const payload = {
      visitor: user.visitor_id,
      roles: []
    };
    const expiredToken = jwt.sign(payload, config.jwt.jwt_secret_key, {
      algorithm: 'HS512',
      expiresIn: '-1s', // Already expired
      audience: 'example.com',
      issuer: 'example.com',
      subject: user.id.toString(),
      jwtid: user.jti
    });

    // Manually add expired token to cache
    const cache = tokenCache();
    cache.set(expiredToken, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    });

    // Verify token is in cache before verification
    expect(cache.has(expiredToken)).toBe(true);

    // Now verification should reach jwt.verify, catch TokenExpiredError, and clean cache
    const result = verifyAccessToken(expiredToken);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('TokenExpiredError');

    // Verify token was removed from cache
    expect(cache.has(expiredToken)).toBe(false);
  });

  test('should handle cache capacity pressure and eviction', () => {
    const cache = tokenCache();
    const originalMax = cache.max;
    
    // Create many tokens to pressure cache
    const tokens: string[] = [];
    const users: AccessTokenPayload[] = [];
    
    // Generate more tokens than cache capacity
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

    // Check that cache size doesn't exceed max
    expect(cache.size).toBeLessThanOrEqual(originalMax);

    // Verify that some early tokens may have been evicted
    let evictedCount = 0;
    for (let i = 0; i < Math.min(10, tokens.length); i++) {
      if (!cache.has(tokens[i])) {
        evictedCount++;
      }
    }

    // At least some early tokens should be evicted if we exceeded capacity
    if (tokens.length > originalMax) {
      expect(evictedCount).toBeGreaterThan(0);
    }

    // Most recent tokens should still be in cache
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

    // Generate tokens
    const tokens = users.map(user => generateAccessToken(user));

    // Perform concurrent verifications
    const verificationPromises = tokens.map(token => 
      Promise.resolve(verifyAccessToken(token))
    );

    const results = await Promise.all(verificationPromises);

    // All verifications should succeed
    results.forEach((result, index) => {
      expect(result.valid).toBe(true);
      expect(result.payload?.visitor).toBe(users[index].visitor_id);
    });
  });

  test('should handle cache TTL configuration', () => {
    const cache = tokenCache();
    
    // Verify cache has TTL configured
    expect(cache.ttl).toBeGreaterThan(0);
    expect(cache.max).toBeGreaterThan(0);

    // Check that TTL is reasonable (should be in milliseconds)
    expect(cache.ttl).toBeLessThan(24 * 60 * 60 * 1000); // Less than 24 hours
    expect(cache.ttl).toBeGreaterThan(1000); // More than 1 second
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
    
    // Verify token works initially
    let result = verifyAccessToken(token);
    expect(result.valid).toBe(true);

    // Corrupt cache entry
    cache.set(token, null as any);

    // Should handle corrupted cache gracefully
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
    
    // Create a valid JWT
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

    // Add incomplete cache entry (missing required fields)
    cache.set(token, { 
      jti: user.jti,
      // Missing visitorId, userId, roles, valid
    } as any);

    // Should handle incomplete cache data gracefully
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
    
    // Create a valid JWT
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

    // Add cache entry with wrong data types
    cache.set(token, { 
      jti: user.jti,
      visitorId: 'not-a-number', // Should be number
      userId: user.id,
      roles: 'not-an-array', // Should be array
      valid: 'not-a-boolean' // Should be boolean
    } as any);

    // The verification will reach JWT verification and fail on visitor ID comparison
    const result = verifyAccessToken(token);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('Invalid visitor id');
  });
});