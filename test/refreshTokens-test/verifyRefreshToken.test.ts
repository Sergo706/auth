import { beforeEach, describe, expect, it } from "vitest";
import { generateRefreshToken, IssuedRefreshToken, verifyRefreshToken } from "../../src/refreshTokens";
import mysql2 from 'mysql2/promise';

  describe('verifyRefreshToken', () => {
    let validToken: IssuedRefreshToken;
    let expiredToken: IssuedRefreshToken;

    beforeEach(async ({testUserId}) => {
      validToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId);
      
      expiredToken = await generateRefreshToken(-1000, testUserId);
    });

    it('should verify a valid token', async ({testUserId}) => {
      const result = await verifyRefreshToken(validToken.raw);

      expect(result.valid).toBe(true);
      expect(result.userId).toBe(testUserId);
      expect(result.visitor_id).toBeDefined();
      expect(result.sessionTTL).toBeInstanceOf(Date);
    });

    it('should work with pre-hashed tokens', async ({testUserId}) => {
      const result = await verifyRefreshToken(validToken.hashedToken, true);

      expect(result.valid).toBe(true);
      expect(result.userId).toBe(testUserId);
    });

    it('should increment usage count', async ({mainPool}) => {
      await verifyRefreshToken(validToken.raw);

      const [rows] = await mainPool.execute<mysql2.RowDataPacket[]>(
        'SELECT usage_count FROM refresh_tokens WHERE token = ?',
        [validToken.hashedToken]
      );

      expect(rows[0].usage_count).toBe(1);
    });

    it('should reject expired tokens', async ({testUserId, mainPool}) => {
      const result = await verifyRefreshToken(expiredToken.raw);

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Token expired');
      expect(result.userId).toBe(testUserId);

      const [rows] = await mainPool.execute<mysql2.RowDataPacket[]>(
        'SELECT valid FROM refresh_tokens WHERE token = ?',
        [expiredToken.hashedToken]
      );
      expect(rows[0].valid).toBe(0);
    });

    it('should reject non-existent tokens', async () => {
      const fakeToken = 'fake'.repeat(32);
      const result = await verifyRefreshToken(fakeToken);

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Token not found');
    });

    it('should reject revoked tokens and delete them', async ({mainPool}) => {
      await mainPool.execute(
        'UPDATE refresh_tokens SET valid = 0 WHERE token = ?',
        [validToken.hashedToken]
      );

      const result = await verifyRefreshToken(validToken.raw);

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Token has been revoked');

      const [rows] = await mainPool.execute<mysql2.RowDataPacket[]>(
        'SELECT * FROM refresh_tokens WHERE token = ?',
        [validToken.hashedToken]
      );
      expect(rows).toHaveLength(0);
    });
  });
