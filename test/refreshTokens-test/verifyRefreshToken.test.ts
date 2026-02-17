import { beforeEach, describe, expect, it } from "vitest";
import { generateRefreshToken, IssuedRefreshToken, verifyRefreshToken } from "../../src/refreshTokens";
import mysql2 from 'mysql2/promise';
import { toDigestHex } from '../../src/jwtAuth/utils/hashChecker';
import { getConfiguration } from '../../src/jwtAuth/config/configuration';

// Helper to compute hashed token from raw
async function hashToken(raw: string): Promise<string> {
  const result = await toDigestHex(raw);
  return result.input;
}

  describe('verifyRefreshToken', () => {
    // Helper to get main pool
    const mainPool = () => getConfiguration().store.main;
    let validToken: IssuedRefreshToken;
    let validTokenHash: string;
    let expiredToken: IssuedRefreshToken;
    let expiredTokenHash: string;

    beforeEach(async ({testUserId}) => {
      validToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId);
      validTokenHash = await hashToken(validToken.raw);
      
      expiredToken = await generateRefreshToken(-1000, testUserId);
      expiredTokenHash = await hashToken(expiredToken.raw);
    });

    it('should verify a valid token', async ({testUserId}) => {
      const result = await verifyRefreshToken(validToken.raw);

      expect(result.valid).toBe(true);
      expect(result.userId).toBe(testUserId);
      expect(result.visitor_id).toBeDefined();
      expect(result.sessionStartedAt).toBeInstanceOf(Date);
    });

    it('should work with pre-hashed tokens', async ({testUserId}) => {
      const result = await verifyRefreshToken(validTokenHash);

      expect(result.valid).toBe(true);
      expect(result.userId).toBe(testUserId);
    });

    it('should increment usage count', async () => {
      await verifyRefreshToken(validToken.raw);

      const [rows] = await mainPool().execute<mysql2.RowDataPacket[]>(
        'SELECT usage_count FROM refresh_tokens WHERE token = ?',
        [validTokenHash]
      );

      expect(rows[0].usage_count).toBe(1);
    });

    it('should reject expired tokens', async ({testUserId}) => {
      const result = await verifyRefreshToken(expiredToken.raw);

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Token expired');
      expect(result.userId).toBe(testUserId);

      const [rows] = await mainPool().execute<mysql2.RowDataPacket[]>(
        'SELECT valid FROM refresh_tokens WHERE token = ?',
        [expiredTokenHash]
      );
      expect(rows[0].valid).toBe(0);
    });

    it('should reject non-existent tokens', async () => {
      const fakeToken = 'fake'.repeat(32);
      const result = await verifyRefreshToken(fakeToken);

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Token not found');
    });

    it('should reject revoked tokens and delete them', async () => {
      await mainPool().execute(
        'UPDATE refresh_tokens SET valid = 0 WHERE token = ?',
        [validTokenHash]
      );

      const result = await verifyRefreshToken(validToken.raw);

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Token has been revoked');

      const [rows] = await mainPool().execute<mysql2.RowDataPacket[]>(
        'SELECT * FROM refresh_tokens WHERE token = ?',
        [validTokenHash]
      );
      expect(rows).toHaveLength(0);
    });
  });

