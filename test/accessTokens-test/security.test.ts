import { describe, test, expect } from 'vitest';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';

import { generateAccessToken, verifyAccessToken, AccessTokenPayload } from '../../src/accessTokens.js';
import './setup.js';

describe('Security Tests', () => {
  test('should reject JWT none algorithm attack', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    // Generate valid token to populate cache
    generateAccessToken(user);

    // Try to create unsigned token (none algorithm attack)
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

  test('should reject token with different algorithm', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID()
    };

    // Generate valid token to populate cache
    generateAccessToken(user);

    // Create token with different algorithm
    const differentAlgPayload = {
      visitor: user.visitor_id,
      roles: []
    };
    const differentAlgToken = jwt.sign(differentAlgPayload, 'test-jwt-secret-key-32-chars-long', {
      algorithm: 'HS256', // Different from configured HS512
      expiresIn: '15m',
      subject: user.id.toString(),
      jwtid: user.jti,
      audience: 'example.com',
      issuer: 'example.com'
    });

    const result = verifyAccessToken(differentAlgToken);

    expect(result.valid).toBe(false);
    expect(['JsonWebTokenError', 'InvalidPayloadType']).toContain(result.errorType);
  });

  test('should handle large payloads', () => {
    const largeRole = 'x'.repeat(1000); // 1KB role name
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: 456,
      jti: crypto.randomUUID(),
      role: [largeRole]
    };

    expect(() => generateAccessToken(user)).not.toThrow();
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
});