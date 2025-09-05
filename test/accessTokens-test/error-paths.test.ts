import { describe, test, expect, vi } from 'vitest';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';

import { generateAccessToken, verifyAccessToken, AccessTokenPayload } from '../../src/accessTokens.js';
import { tokenCache } from '../../src/jwtAuth/utils/accessTokentCache.js';
import { getConfiguration } from '../../src/jwtAuth/config/configuration.js';
import './setup.js';

describe('Error Paths and Unexpected Scenarios', () => {
  test('should handle non-integer user IDs gracefully', () => {
    // Test with string that could be converted to number
    const userWithStringId: any = {
      id: '123',
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const token = generateAccessToken(userWithStringId);
    const result = verifyAccessToken(token);

    expect(result.valid).toBe(true);
    expect(result.payload?.sub).toBe('123');
  });

  test('should handle non-integer visitor IDs gracefully', () => {
    // Test with string that could be converted to number
    const userWithStringVisitorId: any = {
      id: 123,
      visitor_id: '456',
      jti: crypto.randomUUID()
    };

    const token = generateAccessToken(userWithStringVisitorId);
    const result = verifyAccessToken(token);

    expect(result.valid).toBe(true);
    expect(result.payload?.visitor).toBe('456');
  });

  test('should handle floating point IDs', () => {
    const userWithFloatId: any = {
      id: 123.456,
      visitor_id: 789.123,
      jti: crypto.randomUUID()
    };

    const token = generateAccessToken(userWithFloatId);
    const result = verifyAccessToken(token);

    expect(result.valid).toBe(true);
    expect(result.payload?.sub).toBe('123.456');
    expect(result.payload?.visitor).toBe(789.123);
  });

  test('should handle very large IDs (near overflow)', () => {
    const userWithLargeId: AccessTokenPayload = {
      id: 2147483647, // Max 32-bit signed integer
      visitor_id: 9007199254740991, // Max safe integer in JavaScript
      jti: crypto.randomUUID()
    };

    const token = generateAccessToken(userWithLargeId);
    const result = verifyAccessToken(token);

    expect(result.valid).toBe(true);
    expect(result.payload?.sub).toBe('2147483647');
    expect(result.payload?.visitor).toBe(9007199254740991);
  });

  test('should handle negative IDs', () => {
    const userWithNegativeId: any = {
      id: -123,
      visitor_id: -456,
      jti: crypto.randomUUID()
    };

    const token = generateAccessToken(userWithNegativeId);
    const result = verifyAccessToken(token);

    expect(result.valid).toBe(true);
    expect(result.payload?.sub).toBe('-123');
    expect(result.payload?.visitor).toBe(-456);
  });

  test('should handle zero IDs', () => {
    const userWithZeroId: AccessTokenPayload = {
      id: 0,
      visitor_id: 0,
      jti: crypto.randomUUID()
    };

    const token = generateAccessToken(userWithZeroId);
    const result = verifyAccessToken(token);

    expect(result.valid).toBe(true);
    expect(result.payload?.sub).toBe('0');
    expect(result.payload?.visitor).toBe(0);
  });

  test('should force unexpected error type path with mocked jwt.verify', () => {
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

    // Add to cache to pass cache check
    cache.set(token, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    });

    // Mock jwt.verify to throw an unexpected error type
    const originalVerify = jwt.verify;
    const mockError = { unexpected: true, message: 'Unknown error' };
    
    vi.spyOn(jwt, 'verify').mockImplementation(() => {
      throw mockError;
    });

    try {
      const result = verifyAccessToken(token);
      expect(result.valid).toBe(false);
      expect(result.errorType).toBe('Unexpected error type');
    } finally {
      // Restore original function
      vi.mocked(jwt.verify).mockRestore();
    }
  });

  test('should handle jwt signature required error after cache hit', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    // Create token without signature (just header.payload.)
    const header = Buffer.from(JSON.stringify({alg: 'HS512', typ: 'JWT'})).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      visitor: user.visitor_id,
      roles: [],
      aud: 'example.com',
      iss: 'example.com',
      sub: user.id.toString(),
      jti: user.jti
    })).toString('base64url');
    
    const tokenWithoutSignature = `${header}.${payload}.`; // Missing signature

    // Manually add to cache to bypass cache check
    const cache = tokenCache();
    cache.set(tokenWithoutSignature, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    });

    // Now verification should reach jwt.verify and catch missing signature
    const result = verifyAccessToken(tokenWithoutSignature);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('jwt signature is required');
  });

  test('should handle very long JWT tokens', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const config = getConfiguration();
    
    // Create payload with very large data
    const largePayload = {
      visitor: user.visitor_id,
      roles: Array.from({ length: 1000 }, (_, i) => `role${i}`), // 1000 roles
      customData: 'x'.repeat(10000) // 10KB of data
    };

    const largeToken = jwt.sign(largePayload, config.jwt.jwt_secret_key, {
      algorithm: 'HS512',
      expiresIn: '15m',
      audience: 'example.com',
      issuer: 'example.com',
      subject: user.id.toString(),
      jwtid: user.jti
    });

    // Add to cache
    const cache = tokenCache();
    cache.set(largeToken, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: Array.from({ length: 1000 }, (_, i) => `role${i}`), 
      valid: true 
    });

    // Should handle large tokens
    const result = verifyAccessToken(largeToken);
    expect(result.valid).toBe(true);
    expect(result.payload?.roles).toHaveLength(1000);
  });

  test('should handle tokens with null/undefined values in payload', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const config = getConfiguration();
    
    // Create payload with null/undefined values
    const payloadWithNulls = {
      visitor: user.visitor_id,
      roles: null, // null instead of array
      customField: undefined // undefined value
    };

    const tokenWithNulls = jwt.sign(payloadWithNulls, config.jwt.jwt_secret_key, {
      algorithm: 'HS512',
      expiresIn: '15m',
      audience: 'example.com',
      issuer: 'example.com',
      subject: user.id.toString(),
      jwtid: user.jti
    });

    // Add to cache with expected roles
    const cache = tokenCache();
    cache.set(tokenWithNulls, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], // Cache expects empty array, but token has null
      valid: true 
    });

    // When roles is null and cache expects empty array, validation passes (no roles required)
    const result = verifyAccessToken(tokenWithNulls);
    expect(result.valid).toBe(true); // This actually passes because null roles with empty cache roles is valid
  });

  test('should handle malformed roles and trigger MalformedPayload error', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const config = getConfiguration();
    
    // Create payload with malformed roles
    const payloadWithMalformedRoles = {
      visitor: user.visitor_id,
      roles: 'not-an-array' // String instead of array
    };

    const tokenWithMalformedRoles = jwt.sign(payloadWithMalformedRoles, config.jwt.jwt_secret_key, {
      algorithm: 'HS512',
      expiresIn: '15m',
      audience: 'example.com',
      issuer: 'example.com',
      subject: user.id.toString(),
      jwtid: user.jti
    });

    // Add to cache with required roles
    const cache = tokenCache();
    cache.set(tokenWithMalformedRoles, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: ['admin'], // Cache expects admin role
      valid: true 
    });

    // Should handle malformed roles as MalformedPayload
    const result = verifyAccessToken(tokenWithMalformedRoles);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('MalformedPayload');
  });

  test('should handle algorithm none attack attempt', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    // Create a token with 'none' algorithm (security vulnerability attempt)
    const header = Buffer.from(JSON.stringify({alg: 'none', typ: 'JWT'})).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      visitor: user.visitor_id,
      roles: [],
      aud: 'example.com',
      iss: 'example.com',
      sub: user.id.toString(),
      jti: user.jti
    })).toString('base64url');
    
    const noneAlgToken = `${header}.${payload}.`; // No signature with 'none' algorithm

    // Manually add to cache to bypass cache check
    const cache = tokenCache();
    cache.set(noneAlgToken, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    });

    // Should reject 'none' algorithm - this triggers jwt signature required
    const result = verifyAccessToken(noneAlgToken);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('jwt signature is required');
  });

  test('should handle tokens with circular references in payload', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    // Note: JWT.sign will throw if payload has circular references,
    // but we can test the aftermath by manually creating such scenarios
    // This tests the robustness of the verification logic

    const token = generateAccessToken(user);
    
    // Manually corrupt cache with circular reference
    const cache = tokenCache();
    const circularObj: any = { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    };
    circularObj.self = circularObj; // Create circular reference

    cache.set(token, circularObj);

    // Should handle circular references gracefully
    const result = verifyAccessToken(token);
    expect(result.valid).toBe(true); // The verification logic should still work
  });

  test('should handle extremely short JTI values', () => {
    const userWithShortJti: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: 'x' // Very short JTI
    };

    const token = generateAccessToken(userWithShortJti);
    const result = verifyAccessToken(token);

    expect(result.valid).toBe(true);
    expect(result.payload?.jti).toBe('x');
  });

  test('should handle extremely long JTI values', () => {
    const userWithLongJti: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: 'x'.repeat(1000) // Very long JTI
    };

    const token = generateAccessToken(userWithLongJti);
    const result = verifyAccessToken(token);

    expect(result.valid).toBe(true);
    expect(result.payload?.jti).toBe('x'.repeat(1000));
  });
});