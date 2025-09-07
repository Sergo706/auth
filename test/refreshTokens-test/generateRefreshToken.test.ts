// @vitest-environment node

/**
 * @vitest-environment-options { "sequential": true }
 */

import {  describe, expect, it } from "vitest";
import { generateRefreshToken } from "../../src/refreshTokens";
import { createHash } from "crypto";
import mysql2 from 'mysql2/promise';

  

  
describe('generateRefreshToken', () => {

    it('should generate a valid refresh token', async ({testUserId}) => {
      const ttl = 7 * 24 * 60 * 60 * 1000; 
      const result = await generateRefreshToken(ttl, testUserId);

      expect(result).toHaveProperty('raw');
      expect(result).toHaveProperty('hashedToken');
      expect(result).toHaveProperty('expiresAt');
      expect(typeof result.raw).toBe('string');
      expect(result.raw.length).toBe(128);
      expect(typeof result.hashedToken).toBe('string');
      expect(result.hashedToken.length).toBe(64);
      expect(result.expiresAt).toBeInstanceOf(Date);
      expect(result.expiresAt.getTime()).toBeGreaterThan(Date.now());
    });

    it('should hash the token consistently', async ({testUserId}) => {
      const ttl = 24 * 60 * 60 * 1000;
      const result = await generateRefreshToken(ttl, testUserId);
      
      const expectedHash = createHash('sha256').update(result.raw).digest('hex');
      expect(result.hashedToken).toBe(expectedHash);
    });

    it('should store token in database correctly', async ({testUserId, mainPool}) => {
      const ttl = 24 * 60 * 60 * 1000; 
      const result = await generateRefreshToken(ttl, testUserId);

      const [rows] = await mainPool.execute<mysql2.RowDataPacket[]>(
        'SELECT * FROM refresh_tokens WHERE user_id = ? AND token = ?',
        [testUserId, result.hashedToken]
      );

      expect(rows).toHaveLength(1);
      const dbRecord = rows[0];
      expect(dbRecord.user_id).toBe(testUserId);
      expect(dbRecord.token).toBe(result.hashedToken);
      expect(dbRecord.valid).toBe(1);
      expect(Math.abs(new Date(dbRecord.expiresAt).getTime() - result.expiresAt.getTime())).toBeLessThanOrEqual(1000);
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
      expect(token1.hashedToken).not.toBe(token2.hashedToken);
    });
  });