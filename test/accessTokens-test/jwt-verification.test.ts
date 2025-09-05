import { describe, test, expect } from 'vitest';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';

import { generateAccessToken, verifyAccessToken, AccessTokenPayload } from '../../src/accessTokens.js';
import { tokenCache } from '../../src/jwtAuth/utils/accessTokentCache.js';
import { getConfiguration } from '../../src/jwtAuth/config/configuration.js';
import './setup.js';

describe('JWT Verification Branch Coverage', () => {
  test('should reach jwt.verify and catch invalid signature after cache hit', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    // Generate valid token with cache entry
    const token = generateAccessToken(user);
    
    // Verify the token is in cache and valid
    let result = verifyAccessToken(token);
    expect(result.valid).toBe(true);

    // Now create a token with same structure but wrong signature, and manually add to cache
    const payload = {
      visitor: user.visitor_id,
      roles: []
    };
    const maliciousToken = jwt.sign(payload, 'wrong-secret-key', {
      algorithm: 'HS512',
      expiresIn: '15m',
      audience: 'example.com',
      issuer: 'example.com',
      subject: user.id.toString(),
      jwtid: user.jti
    });

    // Manually add the malicious token to cache to bypass cache check
    const cache = tokenCache();
    cache.set(maliciousToken, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    });

    // Now verification should reach jwt.verify and catch invalid signature
    result = verifyAccessToken(maliciousToken);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('invalid signature');
  });

  test('should reach jwt.verify and catch jwt malformed after cache hit', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    // Create a malformed token that will pass cache but fail JWT verification
    const malformedToken = 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.malformed.signature';

    // Manually add to cache to bypass cache check
    const cache = tokenCache();
    cache.set(malformedToken, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    });

    // Now verification should reach jwt.verify and catch malformed JWT
    const result = verifyAccessToken(malformedToken);
    expect(result.valid).toBe(false);
    // The malformed token triggers unexpected error path
    expect(result.errorType).toBe('Unexpected error type');
  });

  test('should reach jwt.verify and catch invalid token after cache hit', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    // Create an invalid token format
    const invalidToken = 'not.a.valid.jwt.token';

    // Manually add to cache to bypass cache check
    const cache = tokenCache();
    cache.set(invalidToken, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    });

    // Now verification should reach jwt.verify and catch invalid token
    const result = verifyAccessToken(invalidToken);
    expect(result.valid).toBe(false);
    // This specific format triggers jwt malformed rather than invalid token
    expect(result.errorType).toBe('jwt malformed');
  });

  test('should reach jwt.verify and catch actual invalid token error', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    // Create a token that looks valid but has invalid structure
    const invalidToken = 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9..'; // Empty payload

    // Manually add to cache to bypass cache check
    const cache = tokenCache();
    cache.set(invalidToken, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    });

    // Now verification should reach jwt.verify and catch invalid token
    const result = verifyAccessToken(invalidToken);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('invalid token');
  });

  test('should reach jwt.verify and catch audience mismatch after cache hit', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const config = getConfiguration();
    
    // Create token with wrong audience
    const payload = {
      visitor: user.visitor_id,
      roles: []
    };
    const tokenWithWrongAudience = jwt.sign(payload, config.jwt.jwt_secret_key, {
      algorithm: 'HS512',
      expiresIn: '15m',
      audience: 'wrong-audience.com', // Different from expected
      issuer: 'example.com',
      subject: user.id.toString(),
      jwtid: user.jti
    });

    // Manually add to cache to bypass cache check
    const cache = tokenCache();
    cache.set(tokenWithWrongAudience, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    });

    // Now verification should reach jwt.verify and catch audience mismatch
    const result = verifyAccessToken(tokenWithWrongAudience);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('JsonWebTokenError');
  });

  test('should reach jwt.verify and catch issuer mismatch after cache hit', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const config = getConfiguration();
    
    // Create token with wrong issuer
    const payload = {
      visitor: user.visitor_id,
      roles: []
    };
    const tokenWithWrongIssuer = jwt.sign(payload, config.jwt.jwt_secret_key, {
      algorithm: 'HS512',
      expiresIn: '15m',
      audience: 'example.com',
      issuer: 'wrong-issuer.com', // Different from expected
      subject: user.id.toString(),
      jwtid: user.jti
    });

    // Manually add to cache to bypass cache check
    const cache = tokenCache();
    cache.set(tokenWithWrongIssuer, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    });

    // Now verification should reach jwt.verify and catch issuer mismatch
    const result = verifyAccessToken(tokenWithWrongIssuer);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('JsonWebTokenError');
  });

  test('should reach jwt.verify and catch subject mismatch after cache hit', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const config = getConfiguration();
    
    // Create token with wrong subject
    const payload = {
      visitor: user.visitor_id,
      roles: []
    };
    const tokenWithWrongSubject = jwt.sign(payload, config.jwt.jwt_secret_key, {
      algorithm: 'HS512',
      expiresIn: '15m',
      audience: 'example.com',
      issuer: 'example.com',
      subject: '999', // Different from expected user.id
      jwtid: user.jti
    });

    // Manually add to cache to bypass cache check
    const cache = tokenCache();
    cache.set(tokenWithWrongSubject, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    });

    // Now verification should reach jwt.verify and catch subject mismatch
    const result = verifyAccessToken(tokenWithWrongSubject);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('JsonWebTokenError');
  });

  test('should reach jwt.verify and catch jwtid mismatch after cache hit', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const config = getConfiguration();
    
    // Create token with wrong jwtid
    const payload = {
      visitor: user.visitor_id,
      roles: []
    };
    const tokenWithWrongJwtid = jwt.sign(payload, config.jwt.jwt_secret_key, {
      algorithm: 'HS512',
      expiresIn: '15m',
      audience: 'example.com',
      issuer: 'example.com',
      subject: user.id.toString(),
      jwtid: 'wrong-jti' // Different from expected
    });

    // Manually add to cache to bypass cache check
    const cache = tokenCache();
    cache.set(tokenWithWrongJwtid, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    });

    // Now verification should reach jwt.verify and catch jwtid mismatch
    const result = verifyAccessToken(tokenWithWrongJwtid);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('JsonWebTokenError');
  });

  test('should reach jwt.verify and catch visitor id mismatch after cache hit', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const config = getConfiguration();
    
    // Create token with wrong visitor id in payload
    const payload = {
      visitor: 999, // Different from cached visitor_id
      roles: []
    };
    const tokenWithWrongVisitor = jwt.sign(payload, config.jwt.jwt_secret_key, {
      algorithm: 'HS512',
      expiresIn: '15m',
      audience: 'example.com',
      issuer: 'example.com',
      subject: user.id.toString(),
      jwtid: user.jti
    });

    // Manually add to cache to bypass cache check
    const cache = tokenCache();
    cache.set(tokenWithWrongVisitor, { 
      jti: user.jti, 
      visitorId: user.visitor_id, // Different from token payload
      userId: user.id, 
      roles: [], 
      valid: true 
    });

    // Now verification should reach jwt.verify and catch visitor mismatch
    const result = verifyAccessToken(tokenWithWrongVisitor);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('Invalid visitor id');
  });

  test('should reach jwt.verify and catch role validation errors after cache hit', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const config = getConfiguration();
    
    // Create token with malformed roles
    const payload = {
      visitor: user.visitor_id,
      roles: 'not-an-array' // Should be array
    };
    const tokenWithMalformedRoles = jwt.sign(payload, config.jwt.jwt_secret_key, {
      algorithm: 'HS512',
      expiresIn: '15m',
      audience: 'example.com',
      issuer: 'example.com',
      subject: user.id.toString(),
      jwtid: user.jti
    });

    // Manually add to cache with expected roles
    const cache = tokenCache();
    cache.set(tokenWithMalformedRoles, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: ['admin'], // Cache expects admin role
      valid: true 
    });

    // Now verification should reach jwt.verify and catch malformed roles
    const result = verifyAccessToken(tokenWithMalformedRoles);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('MalformedPayload');
  });

  test('should reach jwt.verify and catch missing roles after cache hit', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const config = getConfiguration();
    
    // Create token with insufficient roles
    const payload = {
      visitor: user.visitor_id,
      roles: ['user'] // Missing admin role
    };
    const tokenWithMissingRoles = jwt.sign(payload, config.jwt.jwt_secret_key, {
      algorithm: 'HS512',
      expiresIn: '15m',
      audience: 'example.com',
      issuer: 'example.com',
      subject: user.id.toString(),
      jwtid: user.jti
    });

    // Manually add to cache with more required roles
    const cache = tokenCache();
    cache.set(tokenWithMissingRoles, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: ['admin', 'user'], // Cache expects both admin and user roles
      valid: true 
    });

    // Now verification should reach jwt.verify and catch missing roles
    const result = verifyAccessToken(tokenWithMissingRoles);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('InvalidRoles');
  });

  test('should reach jwt.verify and catch extra roles after cache hit', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const config = getConfiguration();
    
    // Create token with extra roles
    const payload = {
      visitor: user.visitor_id,
      roles: ['user', 'admin', 'superuser'] // Extra superuser role
    };
    const tokenWithExtraRoles = jwt.sign(payload, config.jwt.jwt_secret_key, {
      algorithm: 'HS512',
      expiresIn: '15m',
      audience: 'example.com',
      issuer: 'example.com',
      subject: user.id.toString(),
      jwtid: user.jti
    });

    // Manually add to cache with fewer required roles
    const cache = tokenCache();
    cache.set(tokenWithExtraRoles, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: ['user'], // Cache only expects user role
      valid: true 
    });

    // Now verification should reach jwt.verify and catch extra roles
    const result = verifyAccessToken(tokenWithExtraRoles);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('InvalidRoles');
  });
});