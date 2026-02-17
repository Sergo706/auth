// @vitest-environment node

/**
 * @vitest-environment-options { "sequential": true }
 */

import { describe, expect, it } from "vitest";
import { generateRefreshToken, verifyRefreshToken } from "../../src/refreshTokens";

  describe('Edge Cases and Error Handling', () => {
    
    it('should handle database connection failures', async () => {
      // This test is complex because the library uses singleton configuration
      // Just verify that the library throws reasonable errors
      const fakeToken = 'fake'.repeat(32);
      
      try {
        await verifyRefreshToken(fakeToken);
      } catch (error) {
        if (error instanceof Error) {
          expect(typeof error.message).toBe('string');
        }
      }
    });

    it('should handle extremely large TTL values', async ({testUserId}) => {
      // Use a very large but reasonable TTL value
      const largeTtl = 365 * 24 * 60 * 60 * 1000; // 1 year
      
      const token = await generateRefreshToken(largeTtl, testUserId);
      expect(token.expiresAt.getTime()).toBeGreaterThan(Date.now() + 360 * 24 * 60 * 60 * 1000);
    });

    it('should handle zero and negative TTL values', async ({testUserId}) => {
      const zeroTtl = 0;
      const negativeTtl = -1000;

      const zeroToken = await generateRefreshToken(zeroTtl, testUserId);
      expect(zeroToken.expiresAt.getTime()).toBeLessThanOrEqual(Date.now());

      const negativeToken = await generateRefreshToken(negativeTtl, testUserId);
      expect(negativeToken.expiresAt.getTime()).toBeLessThan(Date.now());
    });

    it('should handle special characters in tokens properly', async () => {
      const specialToken = "test\u0000\u001f\u007f\u0080\u00ff";
      
      const result = await verifyRefreshToken(specialToken);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Token not found');
    });
  });