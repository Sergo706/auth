import { beforeEach, describe, expect, it } from "vitest";
import { generateRefreshToken, IssuedRefreshToken, revokeRefreshToken } from "../../src/refreshTokens";
import mysql2 from 'mysql2/promise';
import { toDigestHex } from '../../src/jwtAuth/utils/hashChecker';
import { getConfiguration } from '../../src/jwtAuth/config/configuration';

// Helper to compute hashed token from raw
async function hashToken(raw: string): Promise<string> {
  const result = await toDigestHex(raw);
  return result.input;
}

  describe('revokeRefreshToken', () => {
    // Helper to get main pool
    const mainPool = () => getConfiguration().store.main;
    let validToken: IssuedRefreshToken;
    let validTokenHash: string;

    beforeEach(async ({testUserId}) => {
      validToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId);
      validTokenHash = await hashToken(validToken.raw);
    });

    it('should successfully revoke a valid token', async () => {
      const result = await revokeRefreshToken(validToken.raw);

      expect(result.success).toBe(true);

      const [rows] = await mainPool().execute<mysql2.RowDataPacket[]>(
        'SELECT valid FROM refresh_tokens WHERE token = ?',
        [validTokenHash]
      );
      expect(rows[0].valid).toBe(0);
    });

    it('should work with pre-hashed tokens', async () => {
      const result = await revokeRefreshToken(validTokenHash);

      expect(result.success).toBe(true);

      const [rows] = await mainPool().execute<mysql2.RowDataPacket[]>(
        'SELECT valid FROM refresh_tokens WHERE token = ?',
        [validTokenHash]
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

    it('should only affect the specified token', async ({testUserId}) => {
      const anotherToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId);
      const anotherTokenHash = await hashToken(anotherToken.raw);

      await revokeRefreshToken(validToken.raw);

      const [revokedRows] = await mainPool().execute<mysql2.RowDataPacket[]>(
        'SELECT valid FROM refresh_tokens WHERE token = ?',
        [validTokenHash]
      );
      expect(revokedRows[0].valid).toBe(0);

      const [validRows] = await mainPool().execute<mysql2.RowDataPacket[]>(
        'SELECT valid FROM refresh_tokens WHERE token = ?',
        [anotherTokenHash]
      );
      expect(validRows[0].valid).toBe(1);
    });
  });

