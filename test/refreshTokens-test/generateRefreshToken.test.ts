// @vitest-environment node

/**
 * @vitest-environment-options { "sequential": true }
 */

import {  describe, expect, it } from "vitest";
import { generateRefreshToken } from "../../src/refreshTokens";
import mysql2 from 'mysql2/promise';
import { toDigestHex } from '../../src/jwtAuth/utils/hashChecker';
import { getConfiguration } from '../../src/jwtAuth/config/configuration';

// Helper to compute hashed token from raw
async function hashToken(raw: string): Promise<string> {
  const result = await toDigestHex(raw);
  return result.input;
}

describe('generateRefreshToken', () => {
    // Helper to get main pool
    const mainPool = () => getConfiguration().store.main;

    it('should generate a valid refresh token', async ({testUserId}) => {
      const ttl = 7 * 24 * 60 * 60 * 1000; 
      const result = await generateRefreshToken(ttl, testUserId);

      expect(result).toHaveProperty('raw');
      expect(result).toHaveProperty('expiresAt');
      expect(typeof result.raw).toBe('string');
      expect(result.raw.length).toBe(128);
      expect(result.expiresAt).toBeInstanceOf(Date);
      expect(result.expiresAt.getTime()).toBeGreaterThan(Date.now());
    });

    it('should hash the token consistently', async ({testUserId}) => {
      const ttl = 24 * 60 * 60 * 1000;
      const result = await generateRefreshToken(ttl, testUserId);
      
      const expectedHash = await hashToken(result.raw);
      // Verify the hash is 64 chars (SHA256 hex)
      expect(expectedHash.length).toBe(64);
    });

    it('should store token in database correctly', async ({testUserId}) => {
      const ttl = 24 * 60 * 60 * 1000; 
      const result = await generateRefreshToken(ttl, testUserId);
      const hashedToken = await hashToken(result.raw);

      const [rows] = await mainPool().execute<mysql2.RowDataPacket[]>(
        'SELECT * FROM refresh_tokens WHERE user_id = ? AND token = ?',
        [testUserId, hashedToken]
      );

      expect(rows).toHaveLength(1);
      const dbRecord = rows[0];
      expect(dbRecord.user_id).toBe(testUserId);
      expect(dbRecord.token).toBe(hashedToken);
      expect(dbRecord.valid).toBe(1);
      // Both times should be in UTC - allow a small tolerance for execution time
      const dbExpiresAt = new Date(dbRecord.expiresAt + 'Z').getTime(); // Ensure UTC
      expect(Math.abs(dbExpiresAt - result.expiresAt.getTime())).toBeLessThanOrEqual(5000);
    });

    it('should handle different TTL values correctly', async ({testUserId, anotherUserId}) => {
      const shortTtl = 60 * 1000; 
      const longTtl = 30 * 24 * 60 * 60 * 1000;

      const shortToken = await generateRefreshToken(shortTtl, testUserId);
      const longToken = await generateRefreshToken(longTtl, anotherUserId);

      const timeDiff = longToken.expiresAt.getTime() - shortToken.expiresAt.getTime();
      expect(timeDiff).toBeGreaterThan(29 * 24 * 60 * 60 * 1000); 
    });

    it('should throw error for invalid user ID', async () => {
      const ttl = 24 * 60 * 60 * 1000;
      const invalidUserId = 99999;

      await expect(generateRefreshToken(ttl, invalidUserId)).rejects.toThrow('DB error generating refresh token');
    });

    it('should generate unique tokens for same user', async ({testUserId}) => {
      const ttl = 24 * 60 * 60 * 1000;

      const token1 = await generateRefreshToken(ttl, testUserId);
      const token2 = await generateRefreshToken(ttl, testUserId);

      expect(token1.raw).not.toBe(token2.raw);
      expect(await hashToken(token1.raw)).not.toBe(await hashToken(token2.raw));
    });
  });