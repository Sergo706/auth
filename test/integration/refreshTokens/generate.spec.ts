import { describe, it, expect, beforeAll, beforeEach, inject } from 'vitest';
import { generateRefreshToken } from '../../../src/refreshTokens.js';
import { toDigestHex } from '../../../src/jwtAuth/utils/hashChecker.js';
import { clearTokensForUser, getTokenRow } from '../../test-utils/refreshTokenHelper.js';

describe('generateRefreshToken', () => {
  let testUserId: number;

  beforeAll(() => {
    testUserId = inject('testUserId');
  });

  beforeEach(async () => {
    await clearTokensForUser(testUserId);
  });

  it('should return a 128-char hex raw token and a future expiresAt', async () => {
    const ttl = 15 * 60 * 1000;
    const before = Date.now();
    const result = await generateRefreshToken(ttl, testUserId);
    const after = Date.now();

    expect(result.raw).toMatch(/^[a-f0-9]{128}$/);
    expect(result.expiresAt.getTime()).toBeGreaterThanOrEqual(before + ttl - 1000);
    expect(result.expiresAt.getTime()).toBeLessThanOrEqual(after + ttl + 1000);
  });

  it('should store the hashed token in the DB with correct user_id, valid=1 and usage_count=0', async () => {
    const result = await generateRefreshToken(60_000, testUserId);
    const { input: hash } = await toDigestHex(result.raw);

    const row = await getTokenRow(hash);

    expect(row).not.toBeNull();
    expect(row!.user_id).toBe(testUserId);
    expect(row!.valid).toBe(1);
    expect(row!.usage_count).toBe(0);
  });

  it('should store different hashed tokens for two calls with the same userId', async () => {
    const a = await generateRefreshToken(60_000, testUserId);
    const b = await generateRefreshToken(60_000, testUserId);

    expect(a.raw).not.toBe(b.raw);

    const { input: hashA } = await toDigestHex(a.raw);
    const { input: hashB } = await toDigestHex(b.raw);
    expect(hashA).not.toBe(hashB);
  });

  it('should throw when userId does not exist in DB', async () => {
    await expect(generateRefreshToken(60_000, 999_999)).rejects.toThrow(
      'DB error generating refresh token'
    );
  });
});
