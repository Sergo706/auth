import { describe, it, expect, beforeAll, beforeEach, inject } from 'vitest';
import crypto from 'node:crypto';
import { revokeRefreshToken, generateRefreshToken } from '../../../src/refreshTokens.js';
import { toDigestHex } from '../../../src/jwtAuth/utils/hashChecker.js';
import { clearTokensForUser, getTokenRow } from '../../test-utils/refreshTokenHelper.js';

const TTL = 15 * 60 * 1000;

describe('revokeRefreshToken', () => {
  let testUserId: number;

  beforeAll(() => {
    testUserId = inject('testUserId');
  });

  beforeEach(async () => {
    await clearTokensForUser(testUserId);
  });

  it('should set valid=0 on a valid token and return success:true', async () => {
    const { raw } = await generateRefreshToken(TTL, testUserId);
    const { input: hash } = await toDigestHex(raw);

    const result = await revokeRefreshToken(raw);

    expect(result.success).toBe(true);
    expect((await getTokenRow(hash))!.valid).toBe(0);
  });

  it('should return success:true even when the token does not exist', async () => {
    const unknown = crypto.randomBytes(64).toString('hex');
    const result = await revokeRefreshToken(unknown);

    expect(result.success).toBe(true);
  });

  it('should only revoke the target token and leave others untouched', async () => {
    const target = await generateRefreshToken(TTL, testUserId);
    const other = await generateRefreshToken(TTL, testUserId);
    const { input: targetHash } = await toDigestHex(target.raw);
    const { input: otherHash } = await toDigestHex(other.raw);

    await revokeRefreshToken(target.raw);

    expect((await getTokenRow(targetHash))!.valid).toBe(0);
    expect((await getTokenRow(otherHash))!.valid).toBe(1);
  });
});
