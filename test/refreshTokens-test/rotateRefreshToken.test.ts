// @vitest-environment node

/**
 * @vitest-environment-options { "sequential": true }
 */

import { beforeEach, describe, expect, it } from "vitest";
import { generateRefreshToken, IssuedRefreshToken, rotateRefreshToken } from "../../src/refreshTokens";
import mysql2 from 'mysql2/promise';


  describe('rotateRefreshToken', () => {
    let originalToken: IssuedRefreshToken;
    beforeEach(async ({testUserId, mainPool}) => {
      originalToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId);
        const [exists] = await mainPool.execute<mysql2.RowDataPacket[]>(
        'SELECT 1 FROM refresh_tokens WHERE token = ? LIMIT 1',
        [originalToken.hashedToken])
         expect(exists.length).toBe(1)
    });

    it('should successfully rotate a valid token', async ({testUserId}) => {
      const newTtl = 7 * 24 * 60 * 60 * 1000;
      const result = await rotateRefreshToken(newTtl, testUserId, originalToken.raw);

      expect(result.rotated).toBe(true);
      expect(result.raw).toBeDefined();
      expect(result.hashedToken).toBeDefined();
      expect(result.expiresAt).toBeDefined();
      expect(result.raw).not.toBe(originalToken.raw);
      expect(result.hashedToken).not.toBe(originalToken.hashedToken);
    });

    it('should update database record correctly', async ({testUserId, mainPool}) => {
      const newTtl = 14 * 24 * 60 * 60 * 1000; // 14 days
      const result = await rotateRefreshToken(newTtl, testUserId, originalToken.raw);

      const [oldTokenRows] = await mainPool.execute<mysql2.RowDataPacket[]>(
        'SELECT * FROM refresh_tokens WHERE token = ?',
        [originalToken.hashedToken]
      );
      expect(oldTokenRows).toHaveLength(0);


      const [newTokenRows] = await mainPool.execute<mysql2.RowDataPacket[]>(
        'SELECT * FROM refresh_tokens WHERE token = ?',
        [result.hashedToken]
      );
      expect(newTokenRows).toHaveLength(1);
      expect(newTokenRows[0].user_id).toBe(testUserId);
      expect(newTokenRows[0].valid).toBe(1);
    });

    it('should work with already hashed tokens', async ({testUserId}) => {
      const newTtl = 7 * 24 * 60 * 60 * 1000;
      const result = await rotateRefreshToken(newTtl, testUserId, originalToken.hashedToken, true);

      expect(result.rotated).toBe(true);
      expect(result.raw).toBeDefined();
      expect(result.hashedToken).toBeDefined();
    });

    it('should fail for non-existent token', async ({testUserId}) => {
      const newTtl = 7 * 24 * 60 * 60 * 1000;
      const fakeToken = 'nonexistent'.repeat(16); 
      
      const result = await rotateRefreshToken(newTtl, testUserId, fakeToken);
      expect(result.rotated).toBe(false);
      expect(result.raw).toBeUndefined();
    });

    it('should fail for wrong user ID', async ({anotherUserId}) => {
      const newTtl = 7 * 24 * 60 * 60 * 1000;
      const result = await rotateRefreshToken(newTtl, anotherUserId, originalToken.raw);

      expect(result.rotated).toBe(false);
      expect(result.raw).toBeUndefined();
    });

    it('should fail for invalid user ID', async () => {
      const newTtl = 7 * 24 * 60 * 60 * 1000;
      const invalidUserId = 99999;

      const result = await rotateRefreshToken(newTtl, invalidUserId, originalToken.raw);
      expect(result.rotated).toBe(false);
    });
  });
