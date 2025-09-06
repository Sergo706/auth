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

    const token = generateAccessToken(user);
    
    let result = verifyAccessToken(token);
    expect(result.valid).toBe(true);

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

    const cache = tokenCache();
    cache.set(maliciousToken, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    });

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

    const malformedToken = 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.malformed.signature';

    const cache = tokenCache();
    cache.set(malformedToken, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    });

    const result = verifyAccessToken(malformedToken);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('Unexpected error type');
  });

  test('should reach jwt.verify and catch invalid token after cache hit', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const invalidToken = 'not.a.valid.jwt.token';

    const cache = tokenCache();
    cache.set(invalidToken, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    });

    const result = verifyAccessToken(invalidToken);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('jwt malformed');
  });

  test('should reach jwt.verify and catch actual invalid token error', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const invalidToken = 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9..';

    const cache = tokenCache();
    cache.set(invalidToken, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    });

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
    
    const payload = {
      visitor: user.visitor_id,
      roles: []
    };
    const tokenWithWrongAudience = jwt.sign(payload, config.jwt.jwt_secret_key, {
      algorithm: 'HS512',
      expiresIn: '15m',
      audience: 'wrong-audience.com',
      issuer: 'example.com',
      subject: user.id.toString(),
      jwtid: user.jti
    });

    const cache = tokenCache();
    cache.set(tokenWithWrongAudience, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    });

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
    
    const payload = {
      visitor: user.visitor_id,
      roles: []
    };
    const tokenWithWrongIssuer = jwt.sign(payload, config.jwt.jwt_secret_key, {
      algorithm: 'HS512',
      expiresIn: '15m',
      audience: 'example.com',
      issuer: 'wrong-issuer.com',
      subject: user.id.toString(),
      jwtid: user.jti
    });

    const cache = tokenCache();
    cache.set(tokenWithWrongIssuer, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    });

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
    
    const payload = {
      visitor: user.visitor_id,
      roles: []
    };
    const tokenWithWrongSubject = jwt.sign(payload, config.jwt.jwt_secret_key, {
      algorithm: 'HS512',
      expiresIn: '15m',
      audience: 'example.com',
      issuer: 'example.com',
      subject: '999',
      jwtid: user.jti
    });

    const cache = tokenCache();
    cache.set(tokenWithWrongSubject, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    });

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
      jwtid: 'wrong-jti' 
    });

    const cache = tokenCache();
    cache.set(tokenWithWrongJwtid, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    });

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
    
    const payload = {
      visitor: 999,
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

    const cache = tokenCache();
    cache.set(tokenWithWrongVisitor, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: [], 
      valid: true 
    });

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
    
    const payload = {
      visitor: user.visitor_id,
      roles: 'not-an-array' 
    };
    const tokenWithMalformedRoles = jwt.sign(payload, config.jwt.jwt_secret_key, {
      algorithm: 'HS512',
      expiresIn: '15m',
      audience: 'example.com',
      issuer: 'example.com',
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

  test('should reach jwt.verify and catch missing roles after cache hit', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    const config = getConfiguration();
    
    const payload = {
      visitor: user.visitor_id,
      roles: ['user']
    };
    const tokenWithMissingRoles = jwt.sign(payload, config.jwt.jwt_secret_key, {
      algorithm: 'HS512',
      expiresIn: '15m',
      audience: 'example.com',
      issuer: 'example.com',
      subject: user.id.toString(),
      jwtid: user.jti
    });

    const cache = tokenCache();
    cache.set(tokenWithMissingRoles, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: ['admin', 'user'],
      valid: true 
    });

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
    
    const payload = {
      visitor: user.visitor_id,
      roles: ['user', 'admin', 'superuser']
    };
    const tokenWithExtraRoles = jwt.sign(payload, config.jwt.jwt_secret_key, {
      algorithm: 'HS512',
      expiresIn: '15m',
      audience: 'example.com',
      issuer: 'example.com',
      subject: user.id.toString(),
      jwtid: user.jti
    });

    const cache = tokenCache();
    cache.set(tokenWithExtraRoles, { 
      jti: user.jti, 
      visitorId: user.visitor_id, 
      userId: user.id, 
      roles: ['user'],
      valid: true 
    });

    const result = verifyAccessToken(tokenWithExtraRoles);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('InvalidRoles');
  });
});