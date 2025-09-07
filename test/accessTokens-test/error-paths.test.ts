import { describe, test, expect, vi } from 'vitest';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';

import { generateAccessToken, verifyAccessToken, AccessTokenPayload } from '../../src/accessTokens.js';
import { tokenCache } from '../../src/jwtAuth/utils/accessTokentCache.js';
import { getConfiguration } from '../../src/jwtAuth/config/configuration.js';

describe('Error Paths and Unexpected Scenarios', () => {
  test('should handle non-integer user IDs gracefully', () => {
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
      id: 2147483647, 
      visitor_id: 9007199254740991, 
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
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    });

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
      vi.mocked(jwt.verify).mockRestore();
    }
  });

  test('should handle jwt signature required error after cache hit', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const header = Buffer.from(JSON.stringify({alg: 'HS512', typ: 'JWT'})).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      visitor: user.visitor_id,
      roles: [],
      aud: 'example.com',
      iss: 'example.com',
      sub: user.id.toString(),
      jti: user.jti
    })).toString('base64url');
    
    const tokenWithoutSignature = `${header}.${payload}.`; 

 
    const cache = tokenCache();
    cache.set(tokenWithoutSignature, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    });

    const result = verifyAccessToken(tokenWithoutSignature);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('jwt signature is required');
  });

  test('should handle very long JWT tokens', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID(),
      role: Array.from({ length: 1000 }, (_, i) => `role${i}`)
    };


    
    const largeToken = generateAccessToken(user);


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
    

    const payloadWithNulls = {
      visitor: user.visitor_id,
      roles: null, 
    };

    const tokenWithNulls = jwt.sign(payloadWithNulls, config.jwt.jwt_secret_key, {
      algorithm: 'HS512',
      expiresIn: '15m',
      audience: config.jwt.access_tokens.audience ?? config.jwt.refresh_tokens.domain,
      issuer: config.jwt.access_tokens.issuer ?? config.jwt.refresh_tokens.domain,
      subject: user.id.toString(),
      jwtid: user.jti
    });

    const cache = tokenCache();
    cache.set(tokenWithNulls, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [],
      valid: true 
    });

    const result = verifyAccessToken(tokenWithNulls);
    expect(result.valid).toBe(false); 
    expect(result.errorType).toBe('MalformedPayload');
  });

  test('should handle malformed roles and trigger MalformedPayload error', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const config = getConfiguration();
    
    const payloadWithMalformedRoles = {
      visitor: user.visitor_id,
      roles: 'not-an-array'
    };

    const tokenWithMalformedRoles = jwt.sign(payloadWithMalformedRoles, config.jwt.jwt_secret_key, {
      algorithm: 'HS512',
      expiresIn: '15m',
      audience: config.jwt.access_tokens.audience ?? config.jwt.refresh_tokens.domain,
      issuer: config.jwt.access_tokens.issuer ?? config.jwt.refresh_tokens.domain,
      subject: user.id.toString(),
      jwtid: user.jti
    });

    const cache = tokenCache();
    cache.set(tokenWithMalformedRoles, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: ['admin'],
      valid: true 
    });

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

    const header = Buffer.from(JSON.stringify({alg: 'none', typ: 'JWT'})).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      visitor: user.visitor_id,
      roles: [],
      aud: 'example.com',
      iss: 'example.com',
      sub: user.id.toString(),
      jti: user.jti
    })).toString('base64url');
    
    const noneAlgToken = `${header}.${payload}.`;

    // Manually add to cache to bypass cache check
    const cache = tokenCache();
    cache.set(noneAlgToken, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    });

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
    circularObj.self = circularObj; 

    cache.set(token, circularObj);

    const result = verifyAccessToken(token);
    expect(result.valid).toBe(true);
  });

  test('should handle extremely short JTI values', () => {
    const userWithShortJti: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: 'x'
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
      jti: 'x'.repeat(1000)
    };

    const token = generateAccessToken(userWithLongJti);
    const result = verifyAccessToken(token);

    expect(result.valid).toBe(true);
    expect(result.payload?.jti).toBe('x'.repeat(1000));
  });
});