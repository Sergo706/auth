import { describe, it, expect, beforeAll, beforeEach, inject } from 'vitest';
import {
  revokeAllRefreshTokens,
  generateRefreshToken,
  revokeRefreshToken,
} from '../../../src/refreshTokens.js';
import { clearTokensForUser, countValidTokensForUser } from '../../test-utils/refreshTokenHelper.js';

const TTL = 15 * 60 * 1000;

describe('revokeAllRefreshTokens', () => {
  let testUserId: number;
  let anotherUserId: number;

  beforeAll(() => {
    testUserId = inject('testUserId');
    anotherUserId = inject('anotherUserId');
  });

  beforeEach(async () => {
    await clearTokensForUser(testUserId);
    await clearTokensForUser(anotherUserId);
  });

  it('should revoke all valid tokens for the given userId', async () => {
    await generateRefreshToken(TTL, testUserId);
    await generateRefreshToken(TTL, testUserId);
    await generateRefreshToken(TTL, testUserId);

    const result = await revokeAllRefreshTokens(testUserId);

    expect(result.success).toBe(true);
    expect(await countValidTokensForUser(testUserId)).toBe(0);
  });

  it('should not revoke tokens belonging to other users', async () => {
    await generateRefreshToken(TTL, testUserId);
    await generateRefreshToken(TTL, anotherUserId);
    await generateRefreshToken(TTL, anotherUserId);

    await revokeAllRefreshTokens(testUserId);

    expect(await countValidTokensForUser(anotherUserId)).toBe(2);
  });

  it('should return success:true when the user has no tokens', async () => {
    const result = await revokeAllRefreshTokens(testUserId);
    expect(result.success).toBe(true);
  });

  it('should not error on already-invalid tokens and still return success:true', async () => {
    const a = await generateRefreshToken(TTL, testUserId);
    const b = await generateRefreshToken(TTL, testUserId);
    await revokeRefreshToken(a.raw);
    await revokeRefreshToken(b.raw);

    const result = await revokeAllRefreshTokens(testUserId);

    expect(result.success).toBe(true);
    expect(await countValidTokensForUser(testUserId)).toBe(0);
  });
});
