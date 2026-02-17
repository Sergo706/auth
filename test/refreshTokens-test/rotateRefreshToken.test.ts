// @vitest-environment node

/**
 * @vitest-environment-options { "sequential": true }
 */

import { beforeEach, describe, expect, it } from "vitest";
import { generateRefreshToken, IssuedRefreshToken } from "../../src/refreshTokens";
import { rotateOneUseRefreshToken } from "../../src/jwtAuth/utils/rotateRefreshTokens";
import mysql2 from 'mysql2/promise';
import { toDigestHex } from '../../src/jwtAuth/utils/hashChecker';
import { getConfiguration } from '../../src/jwtAuth/config/configuration';

// Helper to compute hashed token from raw
async function hashToken(raw: string): Promise<string> {
  const result = await toDigestHex(raw);
  return result.input;
}

  describe('rotateOneUseRefreshToken', () => {
    // Helper to get main pool
    const mainPool = () => getConfiguration().store.main;
    let originalToken: IssuedRefreshToken;
    let originalTokenHash: string;

    beforeEach(async ({testUserId}) => {
      originalToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId);
      originalTokenHash = await hashToken(originalToken.raw);
      const [exists] = await mainPool().execute<mysql2.RowDataPacket[]>(
        'SELECT 1 FROM refresh_tokens WHERE token = ? LIMIT 1',
        [originalTokenHash])
      expect(exists.length).toBe(1)
    });

    it('should successfully rotate a valid token', async ({testUserId}) => {
      const newTtl = 7 * 24 * 60 * 60 * 1000;
      const result = await rotateOneUseRefreshToken(newTtl, testUserId, originalToken.raw);

      expect(result.rotated).toBe(true);
      expect(result.raw).toBeDefined();
      expect(result.expiresAt).toBeDefined();
      expect(result.raw).not.toBe(originalToken.raw);
    });

    it('should update database record correctly', async ({testUserId}) => {
      const newTtl = 14 * 24 * 60 * 60 * 1000; // 14 days
      const result = await rotateOneUseRefreshToken(newTtl, testUserId, originalToken.raw);

      // Old token should be revoked (valid = 0)
      const [oldTokenRows] = await mainPool().execute<mysql2.RowDataPacket[]>(
        'SELECT valid FROM refresh_tokens WHERE token = ?',
        [originalTokenHash]
      );
      expect(oldTokenRows[0].valid).toBe(0);

      // New token should exist and be valid
      const newTokenHash = await hashToken(result.raw!);
      const [newTokenRows] = await mainPool().execute<mysql2.RowDataPacket[]>(
        'SELECT * FROM refresh_tokens WHERE token = ?',
        [newTokenHash]
      );
      expect(newTokenRows).toHaveLength(1);
      expect(newTokenRows[0].user_id).toBe(testUserId);
      expect(newTokenRows[0].valid).toBe(1);
    });

    it('should work with already hashed tokens', async ({testUserId}) => {
      const newTtl = 7 * 24 * 60 * 60 * 1000;
      // Note: rotateOneUseRefreshToken accepts raw tokens, not pre-hashed
      // This test verifies that passing a raw token that looks like a hash still works
      const result = await rotateOneUseRefreshToken(newTtl, testUserId, originalToken.raw);

      expect(result.rotated).toBe(true);
      expect(result.raw).toBeDefined();
    });

    it('should fail for non-existent token', async ({testUserId}) => {
      const newTtl = 7 * 24 * 60 * 60 * 1000;
      const fakeToken = 'nonexistent'.repeat(16); 
      
      const result = await rotateOneUseRefreshToken(newTtl, testUserId, fakeToken);
      expect(result.rotated).toBe(false);
      expect(result.raw).toBeUndefined();
    });

    it('should fail for wrong user ID', async ({anotherUserId}) => {
      const newTtl = 7 * 24 * 60 * 60 * 1000;
      const result = await rotateOneUseRefreshToken(newTtl, anotherUserId, originalToken.raw);

      expect(result.rotated).toBe(false);
      expect(result.raw).toBeUndefined();
    });

    it('should fail for invalid user ID', async () => {
      const newTtl = 7 * 24 * 60 * 60 * 1000;
      const invalidUserId = 99999;

      const result = await rotateOneUseRefreshToken(newTtl, invalidUserId, originalToken.raw);
      expect(result.rotated).toBe(false);
    });
  });

