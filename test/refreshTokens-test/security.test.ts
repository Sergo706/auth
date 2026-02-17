// @vitest-environment node

/**
 * @vitest-environment-options { "sequential": true }
 */

import { describe, expect, it } from "vitest";
import { consumeAndVerifyRefreshToken, generateRefreshToken, revokeRefreshToken, verifyRefreshToken } from "../../src/refreshTokens";
import mysql2 from 'mysql2/promise';
import { toDigestHex } from '../../src/jwtAuth/utils/hashChecker';
import { getConfiguration } from '../../src/jwtAuth/config/configuration';

// Helper to compute hashed token from raw
async function hashToken(raw: string): Promise<string> {
  const result = await toDigestHex(raw);
  return result.input;
}

  describe('Security Tests', () => {
    // Helper to get main pool
    const mainPool = () => getConfiguration().store.main;

    it('should prevent SQL injection in token parameters', async () => {
      const maliciousToken = "'; DROP TABLE refresh_tokens; --";
      
      // These should not cause SQL injection
      await expect(verifyRefreshToken(maliciousToken)).resolves.toMatchObject({
        valid: false,
        reason: 'Token not found'
      });

      await expect(revokeRefreshToken(maliciousToken)).resolves.toMatchObject({
        success: true
      });

      // Verify table still exists
      const [rows] = await mainPool().execute('SHOW TABLES LIKE "refresh_tokens"');
      expect(rows).toHaveLength(1);
    });

    it('should handle concurrent token operations safely', async ({testUserId}) => {
      const token = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId);
      const tokenHash = await hashToken(token.raw);

      // Simulate concurrent verification attempts
      const concurrentOps = Array.from({ length: 5 }, () => 
        verifyRefreshToken(token.raw)
      );

      const results = await Promise.all(concurrentOps);
      
      // All should succeed and increment usage count
      results.forEach(result => {
        expect(result.valid).toBe(true);
      });

      // Final usage count should be 5
      const [rows] = await mainPool().execute<mysql2.RowDataPacket[]>(
        'SELECT usage_count FROM refresh_tokens WHERE token = ?',
        [tokenHash]
      );
      expect(rows[0].usage_count).toBe(5);
    });

    it('should detect suspicious token reuse patterns', async ({testUserId}) => {
      const token = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId);
      const tokenHash = await hashToken(token.raw);

      // First consumption should work
      const firstResult = await consumeAndVerifyRefreshToken(token.raw);
      expect(firstResult.valid).toBe(true);

      // Any subsequent consumption should fail
        const secondResult = await consumeAndVerifyRefreshToken(token.raw);
        expect(secondResult.valid).toBe(false);
        expect(secondResult.reason).toBe('Token already used, Please login again');

      // Verify usage count indicates reuse attempt
      const [tokenStatus] = await mainPool().execute<mysql2.RowDataPacket[]>(
        'SELECT usage_count FROM refresh_tokens WHERE token = ?',
        [tokenHash]
      );
      expect(tokenStatus[0].usage_count).toBeGreaterThan(0);
    });

    it('should validate token format and length', async () => {
      const shortToken = 'short';
      const longToken = 'a'.repeat(200);
      const invalidHex = 'zzzz'.repeat(32);

      // These should fail gracefully without errors
      await expect(verifyRefreshToken(shortToken)).resolves.toMatchObject({
        valid: false,
        reason: 'Token not found'
      });

      await expect(verifyRefreshToken(longToken)).resolves.toMatchObject({
        valid: false,
        reason: 'Token not found'
      });

      await expect(verifyRefreshToken(invalidHex)).resolves.toMatchObject({
        valid: false,
        reason: 'Token not found'
      });
    });
  });

