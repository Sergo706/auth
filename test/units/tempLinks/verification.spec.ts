import { describe, it, expect, afterEach, vi } from 'vitest';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { tempJwtLink, verifyTempJwtLink, LinkTokenPayload } from '../../../src/tempLinks.js';
import { magicLinksCache, CacheEntry } from '~~/utils/magicLinksCache.js';
import { configuration, getConfiguration } from '~~/config/configuration.js';
import { newConfig } from '~/test/test-utils/changeConfigs.js';
import { config } from '~/test/configs/config.js';

const makePayload = (): LinkTokenPayload => ({
  visitor: 'visitor-uuid',
  subject: 'user@example.com',
  purpose: 'PASSWORD_RESET',
  jti: crypto.randomUUID(),
});

describe('verifyTempJwtLink', () => {
  it('should verify a valid token and return the payload', () => {
    const payload = makePayload();
    const token = tempJwtLink(payload);

    const result = verifyTempJwtLink(token);

    expect(result.valid).toBe(true);
    expect(result.errorType).toBeUndefined();
    expect(result.payload?.visitor).toBe(payload.visitor);
    expect(result.payload?.purpose).toBe(payload.purpose);
    expect(result.payload?.sub).toBe(payload.subject);
  });

  it('should reject a token not present in the cache', () => {
    const { magic_links } = getConfiguration();
    const token = jwt.sign(
      { visitor: 'visitor-uuid', purpose: 'PASSWORD_RESET' },
      magic_links.jwt_secret_key,
      {
        algorithm: 'HS512',
        subject: 'user@example.com',
        issuer: 'PASSWORD_RESET',
        audience: magic_links.domain,
        jwtid: crypto.randomUUID(),
      }
    );

    const result = verifyTempJwtLink(token);

    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('InvalidPayloadType');
  });

  it('should reject a token when the cache entry is invalidated', () => {
    const payload = makePayload();
    const token = tempJwtLink(payload);
    const entry = magicLinksCache().get(token) as CacheEntry;

    magicLinksCache().set(token, { ...entry, valid: false });

    const result = verifyTempJwtLink(token);

    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('InvalidPayloadType');
  });

  it('should reject an expired token and remove it from the cache', async () => {
    const payload = makePayload();
    const { magic_links } = getConfiguration();

    await configuration(newConfig({ magic_links: { ...magic_links, expiresIn: '-1s' } }));
    const token = tempJwtLink(payload);
    const result = verifyTempJwtLink(token);
    await configuration(config);

    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('TokenExpiredError');
    expect(magicLinksCache().get(token)).toBeUndefined();
  });

  it('should reject a token signed with a different secret', async () => {
    const payload = makePayload();
    const { magic_links } = getConfiguration();

    await configuration(newConfig({ magic_links: { ...magic_links, jwt_secret_key: 'wrong-secret' } }));
    const token = tempJwtLink(payload);
    await configuration(config);

    const result = verifyTempJwtLink(token);

    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('invalid signature');
  });

  it('should reject a token with a mismatched visitor id', () => {
    const payload = makePayload();
    const token = tempJwtLink(payload);
    const entry = magicLinksCache().get(token) as CacheEntry;

    magicLinksCache().set(token, { ...entry, visitor: 'different-visitor' as any });

    const result = verifyTempJwtLink(token);

    expect(result.valid).toBe(false);
    expect(result.errorType).toBe('Invalid visitor id');
  });

  it('should reject malformed tokens', () => {
    const malformed = ['not.a.jwt', 'malformed', '', 'a.b', 'a.b.c.d'];

    malformed.forEach(token => {
      const result = verifyTempJwtLink(token);
      expect(result.valid).toBe(false);
      expect(['jwt malformed', 'invalid token', 'InvalidPayloadType']).toContain(result.errorType);
    });
  });

  describe('jwt.verify error branches', () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('should return jwt signature is required', () => {
      const token = tempJwtLink(makePayload());

      vi.spyOn(jwt, 'verify').mockImplementationOnce(() => {
        throw new jwt.JsonWebTokenError('jwt signature is required');
      });

      const result = verifyTempJwtLink(token);

      expect(result.valid).toBe(false);
      expect(result.errorType).toBe('jwt signature is required');
    });

    it('should return JsonWebTokenError for an unrecognized jwt error message', () => {
      const token = tempJwtLink(makePayload());

      vi.spyOn(jwt, 'verify').mockImplementationOnce(() => {
        throw new jwt.JsonWebTokenError('some unrecognized error');
      });

      const result = verifyTempJwtLink(token);

      expect(result.valid).toBe(false);
      expect(result.errorType).toBe('JsonWebTokenError');
    });

    it('should handle a non-Error thrown from jwt.verify', () => {
      const token = tempJwtLink(makePayload());

      vi.spyOn(jwt, 'verify').mockImplementationOnce(() => {
        throw { message: 'not an Error instance' };
      });

      const result = verifyTempJwtLink(token);

      expect(result.valid).toBe(false);
      expect(result.errorType).toBe('Unexpected error type');
    });

    it('should handle a generic Error not caught by specific branches', () => {
      const token = tempJwtLink(makePayload());

      vi.spyOn(jwt, 'verify').mockImplementationOnce(() => {
        throw new Error('some generic error');
      });

      const result = verifyTempJwtLink(token);

      expect(result.valid).toBe(false);
      expect(result.errorType).toBe('Unexpected error type');
    });
  });
});
