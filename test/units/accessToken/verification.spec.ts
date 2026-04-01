import { describe, it, expect, vi, afterEach } from 'vitest';
import crypto from 'node:crypto';
import jwt, {  SignOptions } from 'jsonwebtoken';
import { generateAccessToken, verifyAccessToken, AccessTokenPayload } from '../../../src/accessTokens.js';
import { configuration, getConfiguration } from '~~/config/configuration.js';
import { newConfig } from '~/test/test-utils/changeConfigs.js';
import { config } from '~/test/configs/config.js';
import { tokenCache, TokenCacheEntry } from '~~/utils/accessTokentCache.js';

describe('verifyAccessToken', () => {
  it('should verify a valid token successfully', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: "456",
      jti: crypto.randomUUID()
    };
    
    const token = generateAccessToken(user);
    const result = verifyAccessToken(token);

    expect(result.valid).toBe(true);
    expect(result.payload).toBeTruthy();
    expect(result.errorType).toBeUndefined();
    expect(result.payload?.visitor).toBe(user.visitor_id);
    expect(result.payload?.sub).toBe(user.id.toString());
  });

  it('should reject token not in cache', () => {
    const payload = {
      id: 123,
      visitor: 456,
      jti: 'random',
      roles: []
    };

    const { jwt: { jwt_secret_key, access_tokens, refresh_tokens } } = getConfiguration();

    const token = jwt.sign(payload, jwt_secret_key, { 
        algorithm: access_tokens.algorithm ?? 'HS512',
        expiresIn: access_tokens.expiresIn as SignOptions["expiresIn"] ?? '15m',
        audience: access_tokens.audience ?? refresh_tokens.domain,
        issuer: access_tokens.issuer ?? refresh_tokens.domain,
        subject: access_tokens.subject ?? payload.id.toString(),
    })

    const result = verifyAccessToken(token);

    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('InvalidPayloadType');
  });

  it('should reject expired token', async () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: "456",
      jti: crypto.randomUUID(),
      role: ['admin']
    };


    const { refresh_tokens,jwt_secret_key  } = getConfiguration().jwt;

    const testConfig = newConfig({
        jwt: {
            access_tokens: {
                expiresIn: '-1s'
            },
            refresh_tokens: { ...refresh_tokens },
            jwt_secret_key
        }
    });

    await configuration(testConfig)
    const token = generateAccessToken(user)
    const result = verifyAccessToken(token);

    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('TokenExpiredError');
  });

  it('should reject malformed token', () => {
    const malformedTokens = [
      'not.a.jwt',
      'malformed',
      '',
      'a.b',
      'a.b.c.d',
      'valid.header.invalidsignature'
    ];

    malformedTokens.forEach(token => {
      const result = verifyAccessToken(token);
      expect(result.valid).toBe(false);
      expect(['jwt malformed', 'invalid token', 'InvalidPayloadType']).toContain(result.errorType);
    });
  });

  it('should reject token with invalid signature', async () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: "456",
      jti: crypto.randomUUID()
    };


    const { refresh_tokens, access_tokens  } = getConfiguration().jwt;

    const testConfig = newConfig({
        jwt: {
            access_tokens: { ...access_tokens },
            refresh_tokens: { ...refresh_tokens },
            jwt_secret_key: "12345"
        }
    })

    await configuration(testConfig)
    const tokenWithInvalidSig = generateAccessToken(user)
    await configuration(config)

    const result = verifyAccessToken(tokenWithInvalidSig);

    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('invalid signature');
  });

  it('should reject token with mismatched visitor ID', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: "456",
      jti: crypto.randomUUID(),
      role: ['admin', 'user']
    };
    const token = generateAccessToken(user);
    const cachedEntry = tokenCache().get(token) as TokenCacheEntry;

    tokenCache().set(token, {
        ...cachedEntry,
        visitorId: "1234"
    });

    const result = verifyAccessToken(token);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('Invalid visitor id');
  });

  it('should validate roles correctly', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: "456",
      jti: crypto.randomUUID(),
      role: ['admin', 'user']
    };

    const token = generateAccessToken(user);
    const result = verifyAccessToken(token);

    expect(result.valid).toBe(true);
    expect(result.payload?.roles).toEqual(['admin', 'user']);
  });

  it('should reject token with malformed roles', () => {
     const user: AccessTokenPayload = {
      id: 123,
      visitor_id: "456",
      jti: crypto.randomUUID(),
      role: ['admin', 'user']
    };

    const token = generateAccessToken(user);
    const cachedEntry = tokenCache().get(token) as TokenCacheEntry;

    tokenCache().set(token, {
        ...cachedEntry,
        roles: 'admin' as any
    });

    const result = verifyAccessToken(token);
    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('MalformedPayload'); 

  });

it('should reject token with missing required roles', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: "456",
      jti: crypto.randomUUID(),
      role: ['admin', 'user'] 
    };

    const token = generateAccessToken(user);
    const cachedEntry = tokenCache().get(token) as TokenCacheEntry;

    tokenCache().set(token, {
        ...cachedEntry,
        roles: ['admin']
    });

    const result = verifyAccessToken(token);

    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('InvalidRoles'); 
  });


  it('should reject token with extra unexpected roles', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: "456",
      jti: crypto.randomUUID(),
      role: ['user'] 
    };
      const token = generateAccessToken(user);
      const cachedEntry = tokenCache().get(token) as TokenCacheEntry;

      tokenCache().set(token, {
        ...cachedEntry,
        roles: ['user', 'admin', 'superuser'] 
      });

      const result = verifyAccessToken(token);
      expect(result.valid).toBe(false);
      expect(result.errorType).toBe('InvalidRoles');
  });

  it('should handle empty roles arrays correctly', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: "456",
      jti: crypto.randomUUID(),
      role: []
    };

    const token = generateAccessToken(user);
    const result = verifyAccessToken(token);

    expect(result.valid).toBe(true);
    expect(result.payload?.roles).toEqual([]);
  });

  it('should reject token when cache entry is invalidated', () => {
    const user: AccessTokenPayload = {
      id: 123,
      visitor_id: "456",
      jti: crypto.randomUUID()
    };

    const token = generateAccessToken(user);
    const cachedEntry = tokenCache().get(token) as TokenCacheEntry;

    tokenCache().set(token, { ...cachedEntry, valid: false });

    const result = verifyAccessToken(token);

    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('InvalidPayloadType');
  });

  describe('jwt.verify error branches', () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('should reject token when jwt.verify throws jwt signature is required', () => {
      const user: AccessTokenPayload = {
        id: 123,
        visitor_id: "456",
        jti: crypto.randomUUID()
      };

      const token = generateAccessToken(user);

      vi.spyOn(jwt, 'verify').mockImplementationOnce(() => {
        throw new jwt.JsonWebTokenError('jwt signature is required');
      });

      const result = verifyAccessToken(token);

      expect(result.valid).toBe(false);
      expect(result.errorType).toBe('jwt signature is required');
    });

    it('should return JsonWebTokenError for unrecognized jwt error message', () => {
      const user: AccessTokenPayload = {
        id: 123,
        visitor_id: "456",
        jti: crypto.randomUUID()
      };

      const token = generateAccessToken(user);

      vi.spyOn(jwt, 'verify').mockImplementationOnce(() => {
        throw new jwt.JsonWebTokenError('some unrecognized error');
      });

      const result = verifyAccessToken(token);

      expect(result.valid).toBe(false);
      expect(result.errorType).toBe('JsonWebTokenError');
    });

    it('should handle non-Error thrown from jwt.verify', () => {
      const user: AccessTokenPayload = {
        id: 123,
        visitor_id: "456",
        jti: crypto.randomUUID()
      };

      const token = generateAccessToken(user);

      vi.spyOn(jwt, 'verify').mockImplementationOnce(() => {
        throw { message: 'not an Error instance' };
      });

      const result = verifyAccessToken(token);

      expect(result.valid).toBe(false);
      expect(result.errorType).toBe('Unexpected error type');
    });

    it('should handle generic Error not caught by specific branches', () => {
      const user: AccessTokenPayload = {
        id: 123,
        visitor_id: "456",
        jti: crypto.randomUUID()
      };

      const token = generateAccessToken(user);

      vi.spyOn(jwt, 'verify').mockImplementationOnce(() => {
        throw new Error('some generic verification error');
      });

      const result = verifyAccessToken(token);

      expect(result.valid).toBe(false);
      expect(result.errorType).toBe('Unexpected error type');
    });
  });
});