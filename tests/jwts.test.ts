import { expect, test, describe, beforeAll, vi, afterEach } from 'vitest'
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
            const beforeGeneration = Math.floor(Date.now() / 1000);
            const token = generateAccessToken(testUser);
            const afterGeneration = Math.floor(Date.now() / 1000);
            
            const parts = token.split(".");
            const decodedPayload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8'));
            
            // Token should expire in approximately 15 minutes (900 seconds)
            const expectedExpiration = beforeGeneration + 900;
            const actualExpiration = decodedPayload.exp;
            
            expect(actualExpiration).toBeGreaterThanOrEqual(expectedExpiration - 5);
            expect(actualExpiration).toBeLessThanOrEqual(afterGeneration + 900 + 5);
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

        test('should return invalid when cache entry is invalid', () => {
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

        test('should handle visitor ID mismatch', () => {
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

        test('should handle malformed token gracefully', () => {
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
    });
});
