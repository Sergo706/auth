import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { tempJwtLink, LinkTokenPayload } from '../../../src/tempLinks.js';
import { magicLinksCache } from '~~/utils/magicLinksCache.js';
import { getConfiguration } from '~~/config/configuration.js';

describe('tempJwtLink', () => {
  it('should return a valid JWT string', () => {
    const payload: LinkTokenPayload = {
      visitor: 'visitor-uuid',
      subject: 'user@example.com',
      purpose: 'PASSWORD_RESET',
      jti: crypto.randomUUID(),
    };

    const token = tempJwtLink(payload);

    expect(token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  });

  it('should sign with the correct standard claims', () => {
    const jti = crypto.randomUUID();
    const payload: LinkTokenPayload = {
      visitor: 'visitor-uuid',
      subject: 'user@example.com',
      purpose: 'PASSWORD_RESET',
      jti,
    };

    const config = getConfiguration();
    const token = tempJwtLink(payload);
    const decoded = jwt.decode(token, { complete: true }) as any;

    expect(decoded.payload.sub).toBe(payload.subject);
    expect(decoded.payload.iss).toBe(payload.purpose);
    expect(decoded.payload.aud).toBe(config.magic_links.domain);
    expect(decoded.payload.jti).toBe(jti);
    expect(decoded.payload.visitor).toBe(payload.visitor);
  });

  it('should strip jti from the body and use it as the JWT jwtid claim', () => {
    const jti = crypto.randomUUID();
    const payload: LinkTokenPayload = {
      visitor: 'visitor-uuid',
      subject: 'user@example.com',
      purpose: 'PASSWORD_RESET',
      jti,
    };

    const token = tempJwtLink(payload);
    const decoded = jwt.decode(token) as any;

    expect(decoded.jti).toBe(jti);
  });

  it('should store the entry in magicLinksCache with valid=true and all fields', () => {
    const payload: LinkTokenPayload = {
      visitor: 'visitor-uuid',
      subject: 'user@example.com',
      purpose: 'MAGIC_LINK_MFA_CHECKS',
      jti: crypto.randomUUID(),
    };

    const token = tempJwtLink(payload);
    const cached = magicLinksCache().get(token);

    expect(cached).toBeTruthy();
    expect(cached!.valid).toBe(true);
    expect(cached!.jti).toBe(payload.jti);
    expect(cached!.visitor).toBe(payload.visitor);
    expect(cached!.subject).toBe(payload.subject);
    expect(cached!.purpose).toBe(payload.purpose);
  });

  it('should include custom claims in the JWT payload', () => {
    const payload: LinkTokenPayload<{ email: string; userId: number }> = {
      visitor: 'visitor-uuid',
      subject: 'user@example.com',
      purpose: 'PASSWORD_RESET',
      jti: crypto.randomUUID(),
      email: 'user@example.com',
      userId: 42,
    };

    const token = tempJwtLink(payload);
    const decoded = jwt.decode(token) as any;

    expect(decoded.email).toBe(payload.email);
    expect(decoded.userId).toBe(payload.userId);
  });

  it('should generate unique tokens for the same subject with different jtis', () => {
    const base = { visitor: 'visitor-uuid', subject: 'user@example.com', purpose: 'PASSWORD_RESET' };
    const a = tempJwtLink({ ...base, jti: crypto.randomUUID() });
    const b = tempJwtLink({ ...base, jti: crypto.randomUUID() });

    expect(a).not.toBe(b);
  });
});
