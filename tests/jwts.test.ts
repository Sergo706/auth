import { expect, test, describe, vi, afterEach } from 'vitest'
import { generateAccessToken, verifyAccessToken, AccessTokenPayload } from '../src/accessTokens.js';
import crypto from 'node:crypto'
import { Buffer } from 'node:buffer';

// Mock dependencies
vi.mock('../src/jwtAuth/config/configuration.js', () => ({
  getConfiguration: vi.fn(() => ({
    jwt: {
      jwt_secret_key: 'test-secret-key-for-testing-only',
      access_tokens: {
        algorithm: 'HS256',
        expiresIn: '15m',
        audience: 'test-audience',
        issuer: 'test-issuer',
        subject: 'test-subject',
        jwtid: 'test-jti',
        maxCacheEntries: 500,
        payload: { custom: 'test-payload' }
      },
      refresh_tokens: {
        domain: 'https://test-domain.com'
      }
    }
  }))
}));

vi.mock('../src/jwtAuth/utils/logger.js', () => ({
  getLogger: vi.fn(() => ({
    child: vi.fn(() => ({
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn()
    }))
  }))
}));

vi.mock('../src/jwtAuth/utils/accessTokentCache.js', () => {
  const cache = new Map();
  return {
    tokenCache: vi.fn(() => ({
      get: vi.fn((token) => cache.get(token)),
      set: vi.fn((token, value) => cache.set(token, value)),
      delete: vi.fn((token) => cache.delete(token)),
      clear: vi.fn(() => cache.clear())
    }))
  };
});

const testUser: AccessTokenPayload = {
    id: 3, 
    visitor_id: 155,
    jti: crypto.randomUUID(),
    role: ['user', 'admin']
}

const basicUser: AccessTokenPayload = {
    id: 1, 
    visitor_id: 100,
    jti: crypto.randomUUID()
}

describe('Access Token Functions', () => {
    afterEach(() => {
        vi.clearAllMocks();
        // Clear the cache between tests to prevent state leakage
        const { tokenCache } = require('../src/jwtAuth/utils/accessTokentCache.js');
        tokenCache().clear();
    });

    describe('generateAccessToken', () => {
        test('should generate a valid JWT access token with user payload', () => {
            const token = generateAccessToken(testUser);
            
            // Verify token structure (header.payload.signature)
            expect(token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
            
            // Decode and verify payload
            const parts = token.split(".");
            expect(parts).toHaveLength(3);
            
            const decodedPayload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8'));
            
            // Verify required claims
            expect(decodedPayload.visitor).toBe(testUser.visitor_id);
            expect(decodedPayload.roles).toEqual(testUser.role);
            expect(decodedPayload.custom).toBe('test-payload'); // from mocked config
            expect(decodedPayload.sub).toBe(testUser.id.toString());
            expect(decodedPayload.jti).toBe(testUser.jti);
            expect(decodedPayload.iss).toBe('test-issuer');
            expect(decodedPayload.aud).toBe('test-audience');
            expect(decodedPayload.exp).toBeDefined();
            expect(decodedPayload.iat).toBeDefined();
        });

        test('should generate token with empty roles array when no roles provided', () => {
            const token = generateAccessToken(basicUser);
            const parts = token.split(".");
            const decodedPayload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8'));
            
            expect(decodedPayload.roles).toEqual([]);
        });

        test('should include additional payload from configuration', () => {
            const token = generateAccessToken(testUser);
            const parts = token.split(".");
            const decodedPayload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8'));
            
            expect(decodedPayload.custom).toBe('test-payload');
        });

        test('should generate unique tokens for different users', () => {
            const token1 = generateAccessToken(testUser);
            const token2 = generateAccessToken(basicUser);
            
            expect(token1).not.toBe(token2);
        });

        test('should generate tokens with correct expiration time', () => {
            // Use deterministic time to avoid flakiness
            const fixedTime = new Date('2024-01-01T12:00:00Z');
            vi.setSystemTime(fixedTime);
            
            const token = generateAccessToken(testUser);
            
            const parts = token.split(".");
            const decodedPayload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8'));
            
            // Token should expire in exactly 15 minutes (900 seconds) from fixed time
            const expectedExpiration = Math.floor(fixedTime.getTime() / 1000) + 900;
            const actualExpiration = decodedPayload.exp;
            
            expect(actualExpiration).toBe(expectedExpiration);
            expect(decodedPayload.iat).toBe(Math.floor(fixedTime.getTime() / 1000));
            
            // Restore real time
            vi.useRealTimers();
        });
    });

    describe('verifyAccessToken', () => {
        test('should return invalid when token is not in cache', () => {
            const token = 'fake.token.here';
            const result = verifyAccessToken(token);
            
            expect(result.valid).toBe(false);
            expect(result.errorType).toBe('InvalidPayloadType');
            expect(result.payload).toBeUndefined();
        });

        test('should return invalid when cache entry is invalid', async () => {
            const { tokenCache } = await import('../src/jwtAuth/utils/accessTokentCache.js');
            const cache = tokenCache();
            const token = 'fake.token.here';
            
            // Mock invalid cache entry
            cache.set(token, { 
                jti: 'test-jti', 
                visitorId: 123, 
                userId: 1, 
                roles: [], 
                valid: false 
            });
            
            const result = verifyAccessToken(token);
            
            expect(result.valid).toBe(false);
            expect(result.errorType).toBe('InvalidPayloadType');
        });

        test('should verify valid token successfully', () => {
            // Generate a real token first
            const token = generateAccessToken(testUser);
            
            const result = verifyAccessToken(token);
            
            expect(result.valid).toBe(true);
            expect(result.payload).toBeDefined();
            expect(result.errorType).toBeUndefined();
        });

        test('should handle visitor ID mismatch', async () => {
            const token = generateAccessToken(testUser);
            const { tokenCache } = await import('../src/jwtAuth/utils/accessTokentCache.js');
            const cache = tokenCache();
            
            // Modify cache to have different visitor ID
            cache.set(token, { 
                jti: testUser.jti, 
                visitorId: 999, // Different visitor ID
                userId: testUser.id, 
                roles: testUser.role || [], 
                valid: true 
            });
            
            const result = verifyAccessToken(token);
            
            expect(result.valid).toBe(false);
            expect(result.errorType).toBe('Invalid visitor id');
        });

        test('should handle malformed token gracefully', async () => {
            const malformedToken = 'not.a.jwt';
            const { tokenCache } = await import('../src/jwtAuth/utils/accessTokentCache.js');
            const cache = tokenCache();
            
            // Set valid cache entry
            cache.set(malformedToken, { 
                jti: 'test-jti', 
                visitorId: 123, 
                userId: 1, 
                roles: [], 
                valid: true 
            });
            
            const result = verifyAccessToken(malformedToken);
            
            expect(result.valid).toBe(false);
            expect(result.errorType).toBe('jwt malformed');
        });

        test('should handle role validation correctly', () => {
            const userWithRoles: AccessTokenPayload = {
                id: 5,
                visitor_id: 200,
                jti: crypto.randomUUID(),
                role: ['admin', 'user']
            };
            
            const token = generateAccessToken(userWithRoles);
            const result = verifyAccessToken(token);
            
            expect(result.valid).toBe(true);
            expect(result.payload).toBeDefined();
        });

        test('should handle expired token and trigger cache deletion', () => {
            // Generate token with past expiration
            const pastTime = new Date('2020-01-01T12:00:00Z');
            vi.setSystemTime(pastTime);
            
            const token = generateAccessToken(testUser);
            
            // Move to future time to make token expired
            const futureTime = new Date('2025-01-01T12:00:00Z');
            vi.setSystemTime(futureTime);
            
            const result = verifyAccessToken(token);
            
            expect(result.valid).toBe(false);
            expect(result.errorType).toBe('TokenExpiredError');
            
            vi.useRealTimers();
        });

        test('should handle jwt.verify returning string instead of object', () => {
            // Mock jwt.verify to return a string
            const jwt = require('jsonwebtoken');
            const originalVerify = jwt.verify;
            jwt.verify = vi.fn().mockReturnValue('string-instead-of-object');
            
            try {
                const token = generateAccessToken(testUser);
                const result = verifyAccessToken(token);
                
                expect(result.valid).toBe(false);
                expect(result.errorType).toBe('InvalidPayloadType');
            } finally {
                jwt.verify = originalVerify;
            }
        });

        test('should handle non-Error thrown values', () => {
            // Mock jwt.verify to throw a primitive value
            const jwt = require('jsonwebtoken');
            const originalVerify = jwt.verify;
            jwt.verify = vi.fn().mockImplementation(() => {
                throw 'primitive-error';
            });
            
            try {
                const token = generateAccessToken(testUser);
                const result = verifyAccessToken(token);
                
                expect(result.valid).toBe(false);
                expect(result.errorType).toBe('Unexpected error type');
            } finally {
                jwt.verify = originalVerify;
            }
        });

        test('should handle missing roles in token when required roles present', () => {
            const token = generateAccessToken(testUser);
            
            // Mock cache to have required roles but token has different roles
            const { tokenCache } = require('../src/jwtAuth/utils/accessTokentCache.js');
            const cache = tokenCache();
            cache.set(token, { 
                jti: testUser.jti, 
                visitorId: testUser.visitor_id, 
                userId: testUser.id, 
                roles: ['superuser'], // Required role not in token
                valid: true 
            });
            
            const result = verifyAccessToken(token);
            
            expect(result.valid).toBe(false);
            expect(result.errorType).toBe('InvalidRoles');
        });

        test('should handle extra roles in token', () => {
            const userWithExtraRoles: AccessTokenPayload = {
                id: 6,
                visitor_id: 300,
                jti: crypto.randomUUID(),
                role: ['user', 'admin', 'superuser']
            };
            
            const token = generateAccessToken(userWithExtraRoles);
            
            // Mock cache to have fewer required roles
            const { tokenCache } = require('../src/jwtAuth/utils/accessTokentCache.js');
            const cache = tokenCache();
            cache.set(token, { 
                jti: userWithExtraRoles.jti, 
                visitorId: userWithExtraRoles.visitor_id, 
                userId: userWithExtraRoles.id, 
                roles: ['user'], // Token has extra roles
                valid: true 
            });
            
            const result = verifyAccessToken(token);
            
            expect(result.valid).toBe(false);
            expect(result.errorType).toBe('InvalidRoles');
        });

        test('should handle malformed roles in token (non-array)', () => {
            const jwt = require('jsonwebtoken');
            const originalVerify = jwt.verify;
            
            // Mock jwt.verify to return payload with non-array roles
            jwt.verify = vi.fn().mockReturnValue({
                visitor: testUser.visitor_id,
                roles: 'not-an-array', // Invalid roles format
                sub: testUser.id.toString(),
                jti: testUser.jti,
                aud: 'test-audience',
                iss: 'test-issuer'
            });
            
            try {
                const token = generateAccessToken(testUser);
                const result = verifyAccessToken(token);
                
                expect(result.valid).toBe(false);
                expect(result.errorType).toBe('MalformedPayload');
            } finally {
                jwt.verify = originalVerify;
            }
        });

        test('should handle malformed roles in token (non-string array elements)', () => {
            const jwt = require('jsonwebtoken');
            const originalVerify = jwt.verify;
            
            // Mock jwt.verify to return payload with invalid role elements
            jwt.verify = vi.fn().mockReturnValue({
                visitor: testUser.visitor_id,
                roles: ['user', 123, 'admin'], // Contains non-string elements
                sub: testUser.id.toString(),
                jti: testUser.jti,
                aud: 'test-audience',
                iss: 'test-issuer'
            });
            
            try {
                const token = generateAccessToken(testUser);
                const result = verifyAccessToken(token);
                
                expect(result.valid).toBe(false);
                expect(result.errorType).toBe('MalformedPayload');
            } finally {
                jwt.verify = originalVerify;
            }
        });

        test('should pass verification when no roles required (empty array)', () => {
            const token = generateAccessToken(basicUser); // User with no roles
            
            // Mock cache with empty required roles
            const { tokenCache } = require('../src/jwtAuth/utils/accessTokentCache.js');
            const cache = tokenCache();
            cache.set(token, { 
                jti: basicUser.jti, 
                visitorId: basicUser.visitor_id, 
                userId: basicUser.id, 
                roles: [], // No roles required
                valid: true 
            });
            
            const result = verifyAccessToken(token);
            
            expect(result.valid).toBe(true);
            expect(result.payload).toBeDefined();
        });

        test('should handle various JWT error types correctly', () => {
            const jwt = require('jsonwebtoken');
            const originalVerify = jwt.verify;
            
            const testCases = [
                { message: 'invalid token', expectedError: 'invalid token' },
                { message: 'jwt signature is required', expectedError: 'jwt signature is required' },
                { message: 'invalid signature', expectedError: 'invalid signature' },
                { message: 'some other jwt error', expectedError: 'JsonWebTokenError' }
            ];
            
            testCases.forEach(({ message, expectedError }) => {
                jwt.verify = vi.fn().mockImplementation(() => {
                    const error = new jwt.JsonWebTokenError(message);
                    throw error;
                });
                
                const token = generateAccessToken(testUser);
                const result = verifyAccessToken(token);
                
                expect(result.valid).toBe(false);
                expect(result.errorType).toBe(expectedError);
            });
            
            jwt.verify = originalVerify;
        });

        test('should handle issuer mismatch', () => {
            const jwt = require('jsonwebtoken');
            const originalVerify = jwt.verify;
            
            jwt.verify = vi.fn().mockImplementation(() => {
                const error = new jwt.JsonWebTokenError('jwt issuer invalid. expected: test-issuer');
                throw error;
            });
            
            try {
                const token = generateAccessToken(testUser);
                const result = verifyAccessToken(token);
                
                expect(result.valid).toBe(false);
                expect(result.errorType).toBe('JsonWebTokenError');
            } finally {
                jwt.verify = originalVerify;
            }
        });

        test('should handle audience mismatch', () => {
            const jwt = require('jsonwebtoken');
            const originalVerify = jwt.verify;
            
            jwt.verify = vi.fn().mockImplementation(() => {
                const error = new jwt.JsonWebTokenError('jwt audience invalid. expected: test-audience');
                throw error;
            });
            
            try {
                const token = generateAccessToken(testUser);
                const result = verifyAccessToken(token);
                
                expect(result.valid).toBe(false);
                expect(result.errorType).toBe('JsonWebTokenError');
            } finally {
                jwt.verify = originalVerify;
            }
        });

        test('should handle algorithm mismatch', () => {
            const jwt = require('jsonwebtoken');
            const originalVerify = jwt.verify;
            
            jwt.verify = vi.fn().mockImplementation(() => {
                const error = new jwt.JsonWebTokenError('invalid algorithm');
                throw error;
            });
            
            try {
                const token = generateAccessToken(testUser);
                const result = verifyAccessToken(token);
                
                expect(result.valid).toBe(false);
                expect(result.errorType).toBe('JsonWebTokenError');
            } finally {
                jwt.verify = originalVerify;
            }
        });

        test('should handle subject mismatch', () => {
            const jwt = require('jsonwebtoken');
            const originalVerify = jwt.verify;
            
            jwt.verify = vi.fn().mockImplementation(() => {
                const error = new jwt.JsonWebTokenError('jwt subject invalid. expected: 3');
                throw error;
            });
            
            try {
                const token = generateAccessToken(testUser);
                const result = verifyAccessToken(token);
                
                expect(result.valid).toBe(false);
                expect(result.errorType).toBe('JsonWebTokenError');
            } finally {
                jwt.verify = originalVerify;
            }
        });

        test('should handle jwtid mismatch', () => {
            const jwt = require('jsonwebtoken');
            const originalVerify = jwt.verify;
            
            jwt.verify = vi.fn().mockImplementation(() => {
                const error = new jwt.JsonWebTokenError('jwt id invalid. expected: ' + testUser.jti);
                throw error;
            });
            
            try {
                const token = generateAccessToken(testUser);
                const result = verifyAccessToken(token);
                
                expect(result.valid).toBe(false);
                expect(result.errorType).toBe('JsonWebTokenError');
            } finally {
                jwt.verify = originalVerify;
            }
        });

        test('should verify critical JWT claims in successful verification', () => {
            const token = generateAccessToken(testUser);
            const result = verifyAccessToken(token);
            
            expect(result.valid).toBe(true);
            expect(result.payload).toBeDefined();
            
            if (result.payload) {
                expect(result.payload.sub).toBe(testUser.id.toString());
                expect(result.payload.jti).toBe(testUser.jti);
                expect(result.payload.aud).toBe('test-audience');
                expect(result.payload.iss).toBe('test-issuer');
                expect(result.payload.visitor).toBe(testUser.visitor_id);
                expect(result.payload.roles).toEqual(testUser.role);
            }
        });

        test('should handle malformed token with trailing space', () => {
            const malformedToken = 'header.payload.signature '; // trailing space
            const { tokenCache } = require('../src/jwtAuth/utils/accessTokentCache.js');
            const cache = tokenCache();
            
            cache.set(malformedToken, { 
                jti: 'test-jti', 
                visitorId: 123, 
                userId: 1, 
                roles: [], 
                valid: true 
            });
            
            const result = verifyAccessToken(malformedToken);
            
            expect(result.valid).toBe(false);
            expect(result.errorType).toBe('jwt malformed');
        });
    });
});
