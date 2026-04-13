import { describe, it, expect, beforeAll, beforeEach, inject } from 'vitest';
import crypto from 'node:crypto';
import {
  verifyRefreshToken,
  generateRefreshToken,
  revokeRefreshToken,
} from '../../../src/refreshTokens.js';
import { toDigestHex } from '../../../src/jwtAuth/utils/hashChecker.js';
import {
  clearTokensForUser,
  getTokenRow,
  insertRefreshToken,
} from '../../test-utils/refreshTokenHelper.js';

const TTL = 15 * 60 * 1000;

describe('verifyRefreshToken', () => {
  let testUserId: number;

  beforeAll(() => {
    testUserId = inject('testUserId');
  });

  beforeEach(async () => {
    await clearTokensForUser(testUserId);
  });

  it('should return valid:true with full metadata', async () => {
    const { raw } = await generateRefreshToken(TTL, testUserId);

    const result = await verifyRefreshToken(raw);

    expect(result.valid).toBe(true);
    expect(result.userId).toBe(testUserId);
    expect(typeof result.visitor_id).toBe('string');
    expect(result.sessionStartedAt).toBeInstanceOf(Date);
    expect(result.expiresAt).toBeInstanceOf(Date);
  });

  it('should reject an unknown token with Token not found', async () => {
    const unknown = crypto.randomBytes(64).toString('hex');
    const result = await verifyRefreshToken(unknown);

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Token not found');
  });

  it('should delete the revoked token row and return Token has been revoked', async () => {
    const { raw } = await generateRefreshToken(TTL, testUserId);
    const { input: hash } = await toDigestHex(raw);
    await revokeRefreshToken(raw);

    const result = await verifyRefreshToken(raw);

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Token has been revoked');
    expect(await getTokenRow(hash)).toBeNull();
  });

  it('should mark the token invalid and return Token expired', async () => {
    const { raw, hash } = await insertRefreshToken({ userId: testUserId, ttlSeconds: -1 });

    const result = await verifyRefreshToken(raw);

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Token expired');
    expect(result.userId).toBe(testUserId);

    const row = await getTokenRow(hash);
    expect(row!.valid).toBe(0);
  });
});
