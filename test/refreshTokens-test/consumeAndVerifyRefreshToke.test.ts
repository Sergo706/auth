// @vitest-environment node

/**
 * @vitest-environment-options { "sequential": true }
 */

import { beforeEach, describe, expect, it } from "vitest";
import { consumeAndVerifyRefreshToken, generateRefreshToken, IssuedRefreshToken, verifyRefreshToken } from "../../src/refreshTokens";
import mysql2 from 'mysql2/promise';
import { toDigestHex } from '../../src/jwtAuth/utils/hashChecker';
import { getConfiguration } from '../../src/jwtAuth/config/configuration';

// Helper to compute hashed token from raw
async function hashToken(raw: string): Promise<string> {
  const result = await toDigestHex(raw);
  return result.input;
}

  describe('consumeAndVerifyRefreshToken', () => {
    // Helper to get main pool
    const mainPool = () => getConfiguration().store.main;
    let validToken: IssuedRefreshToken;
    let validTokenHash: string;

    beforeEach(async ({testUserId}) => {
      validToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId);
      validTokenHash = await hashToken(validToken.raw);
    });

    it('should consume a valid token successfully', async ({testUserId}) => {
      const result = await consumeAndVerifyRefreshToken(validToken.raw);

      expect(result.valid).toBe(true);
      expect(result.userId).toBe(testUserId);
      expect(result.visitor_id).toBeDefined();
      expect(result.sessionTTL).toBeInstanceOf(Date);

      // Token should have usage_count = 1
      const [rows] = await mainPool().execute<mysql2.RowDataPacket[]>(
        'SELECT usage_count FROM refresh_tokens WHERE token = ?',
        [validTokenHash]
      );
      expect(rows[0].usage_count).toBe(1);
    });



    it('should detect and prevent token reuse attacks', async () => {
      const firstResult = await consumeAndVerifyRefreshToken(validToken.raw);
      expect(firstResult.valid).toBe(true);

        const secondResult = await consumeAndVerifyRefreshToken(validToken.raw);
        expect(secondResult.valid).toBe(false);
        expect(secondResult.reason).toBe('Token already used, Please login again');


      const [rows] = await mainPool().execute<mysql2.RowDataPacket[]>(
        'SELECT usage_count FROM refresh_tokens WHERE token = ?',
        [validTokenHash]
      );
      expect(rows[0].usage_count).toBeGreaterThan(0);
    });

    it('should revoke all other valid tokens for a user upon detecting token reuse', async ({testUserId}) => {
      const tokenA = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId);
      const tokenB = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId);

      const initialCheck = await verifyRefreshToken(tokenB.raw);
      expect(initialCheck.valid).toBe(true);


      await consumeAndVerifyRefreshToken(tokenA.raw); // First use is successful
      await consumeAndVerifyRefreshToken(tokenA.raw); // Second use triggers revocation

      // 3. Verification: Check that the second, unused token (tokenB) has been revoked
      const finalResult = await verifyRefreshToken(tokenB.raw);
      expect(finalResult.valid).toBe(false);
      expect(finalResult.reason).toBe('Token has been revoked');
    });

    it('should work with pre-hashed tokens', async ({testUserId}) => {
      const result = await consumeAndVerifyRefreshToken(validTokenHash);

      expect(result.valid).toBe(true);
      expect(result.userId).toBe(testUserId);
    });

    it('should handle expired tokens properly', async ({testUserId}) => {
      // Tokens created with negative TTL are immediately invalid
      const expiredToken = await generateRefreshToken(-1000, testUserId);
      const result = await consumeAndVerifyRefreshToken(expiredToken.raw);

      expect(result.valid).toBe(false);
      // Token created with negative TTL returns 'Invalid token' (no userId returned)
      expect(result.reason).toBe('Invalid token');
    });

    it('should handle revoked tokens properly', async () => {
      // Revoke the token first
      await mainPool().execute(
        'UPDATE refresh_tokens SET valid = 0 WHERE token = ?',
        [validTokenHash]
      );
  
        const result = await consumeAndVerifyRefreshToken(validToken.raw);
        expect(result.valid).toBe(false);
        expect(result.reason).toBe('Token has been revoked');
    });

    it('should handle non-existent tokens', async () => {
      const fakeToken = 'fake'.repeat(32);
      
        const result = await consumeAndVerifyRefreshToken(fakeToken);
        expect(result.valid).toBe(false);
        expect(result.reason).toBe('Token not found');
    });

    it('should maintain transaction integrity', async () => {
      const result = await consumeAndVerifyRefreshToken(validToken.raw);
      expect(result.valid).toBe(true);

      const [rows] = await mainPool().execute<mysql2.RowDataPacket[]>(
        'SELECT usage_count, valid FROM refresh_tokens WHERE token = ?',
        [validTokenHash]
      );
      expect(rows[0].usage_count).toBe(1);
      expect(rows[0].valid).toBe(1);
    });
  });