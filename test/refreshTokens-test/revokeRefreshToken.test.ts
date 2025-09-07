// @vitest-environment node

/**
 * @vitest-environment-options { "sequential": true }
 */

import { beforeEach, describe, expect, it } from "vitest";
import { generateRefreshToken, IssuedRefreshToken, revokeRefreshToken } from "../../src/refreshTokens";
import mysql2 from 'mysql2/promise';


  describe('revokeRefreshToken', () => {
    let validToken: IssuedRefreshToken;


    beforeEach(async ({testUserId}) => {
      validToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId);
    });

    it('should successfully revoke a valid token', async ({mainPool}) => {
      const result = await revokeRefreshToken(validToken.raw);

      expect(result.success).toBe(true);

      const [rows] = await mainPool.execute<mysql2.RowDataPacket[]>(
        'SELECT valid FROM refresh_tokens WHERE token = ?',
        [validToken.hashedToken]
      );
      expect(rows[0].valid).toBe(0);
    });

    it('should work with pre-hashed tokens', async ({mainPool}) => {
      const result = await revokeRefreshToken(validToken.hashedToken, true);

      expect(result.success).toBe(true);

      const [rows] = await mainPool.execute<mysql2.RowDataPacket[]>(
        'SELECT valid FROM refresh_tokens WHERE token = ?',
        [validToken.hashedToken]
      );
      expect(rows[0].valid).toBe(0);
    });

    it('should handle already revoked tokens gracefully', async () => {
      await revokeRefreshToken(validToken.raw);
      
      const result = await revokeRefreshToken(validToken.raw);
      expect(result.success).toBe(true);
    });

    it('should handle non-existent tokens gracefully', async () => {
      const fakeToken = 'fake'.repeat(32);
      const result = await revokeRefreshToken(fakeToken);

      expect(result.success).toBe(true);
    });

    it('should only affect the specified token', async ({mainPool, testUserId}) => {
      const anotherToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId);

      await revokeRefreshToken(validToken.raw);

      const [revokedRows] = await mainPool.execute<mysql2.RowDataPacket[]>(
        'SELECT valid FROM refresh_tokens WHERE token = ?',
        [validToken.hashedToken]
      );
      expect(revokedRows[0].valid).toBe(0);

      const [validRows] = await mainPool.execute<mysql2.RowDataPacket[]>(
        'SELECT valid FROM refresh_tokens WHERE token = ?',
        [anotherToken.hashedToken]
      );
      expect(validRows[0].valid).toBe(1);
    });
  });
