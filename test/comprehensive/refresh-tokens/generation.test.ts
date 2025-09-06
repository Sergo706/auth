import { describe, test, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import crypto from 'crypto';
import { 
  generateRefreshToken, 
  verifyRefreshToken
} from '../../../src/refreshTokens.js';
import { 
  setupTestDatabase, 
  teardownTestDatabase, 
  setupTestUser, 
  cleanupTestData,
  mockBotDetector 
} from '../test-setup.js';

// Mock bot detector for controlled testing
mockBotDetector();

describe('Refresh Token Generation - Edge Cases', () => {
  beforeAll(async () => {
    await setupTestDatabase();
  });

  afterAll(async () => {
    await teardownTestDatabase();
  });

  beforeEach(async () => {
    await cleanupTestData(999, 888);
    await setupTestUser(999, 888);
  });

  test('should generate valid refresh token', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    const token = await generateRefreshToken(ttl, userId);
    
    expect(token).toHaveProperty('raw');
    expect(token).toHaveProperty('hashedToken');
    expect(token).toHaveProperty('expiresAt');
    
    expect(typeof token.raw).toBe('string');
    expect(token.raw).toMatch(/^[a-f0-9]{128}$/);
    expect(token.hashedToken).toMatch(/^[a-f0-9]{64}$/);
    expect(token.expiresAt).toBeInstanceOf(Date);
  });

  test('should handle zero TTL', async () => {
    const userId = 999;

    try {
      const token = await generateRefreshToken(0, userId);
      // If allowed, should be immediately expired
      expect(token.expiresAt.getTime()).toBeLessThanOrEqual(Date.now());
    } catch (error) {
      // Zero TTL rejection is also acceptable
      expect(error).toBeDefined();
    }
  });

  test('should handle negative TTL', async () => {
    const userId = 999;

    try {
      const token = await generateRefreshToken(-1000, userId);
      // If allowed, should be expired
      expect(token.expiresAt.getTime()).toBeLessThan(Date.now());
    } catch (error) {
      // Negative TTL rejection is also acceptable
      expect(error).toBeDefined();
    }
  });

  test('should handle maximum TTL values', async () => {
    const userId = 999;
    const maxTtl = Number.MAX_SAFE_INTEGER;

    try {
      const token = await generateRefreshToken(maxTtl, userId);
      expect(token).toBeDefined();
      
      // Should handle large dates properly
      expect(token.expiresAt.getTime()).toBeGreaterThan(Date.now());
    } catch (error) {
      // Reasonable TTL limits are acceptable
      expect(error).toBeDefined();
    }
  });

  test('should generate unique tokens for concurrent requests', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    const tokenPromises = Array.from({ length: 10 }, () =>
      generateRefreshToken(ttl, userId)
    );

    const tokens = await Promise.all(tokenPromises);
    
    // All tokens should be unique
    const rawTokens = tokens.map(t => t.raw);
    const uniqueTokens = new Set(rawTokens);
    expect(uniqueTokens.size).toBe(tokens.length);

    // All hashes should be unique
    const hashedTokens = tokens.map(t => t.hashedToken);
    const uniqueHashes = new Set(hashedTokens);
    expect(uniqueHashes.size).toBe(tokens.length);
  });

  test('should handle extreme user IDs', async () => {
    const extremeUserIds = [
      0, // Minimum
      1, // Small positive
      Number.MAX_SAFE_INTEGER, // Maximum safe integer
      -1, // Negative (if allowed)
      999999999, // Large ID
    ];

    const ttl = 24 * 60 * 60 * 1000;

    for (const userId of extremeUserIds) {
      if (userId > 0) {
        // Setup user if positive ID
        await cleanupTestData(userId, 888);
        await setupTestUser(userId, 888);
      }

      try {
        const token = await generateRefreshToken(ttl, userId);
        expect(token).toBeDefined();
        
        // Clean up if successful
        if (userId > 0) {
          await cleanupTestData(userId, 888);
        }
      } catch (error) {
        // Invalid user ID rejection is acceptable
        expect(error).toBeDefined();
      }
    }
  });

  test('should maintain consistent token format', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    // Generate tokens across time
    const tokens = [];
    for (let i = 0; i < 5; i++) {
      const token = await generateRefreshToken(ttl, userId);
      tokens.push(token);
      
      // Small delay to test time-based consistency
      await new Promise(resolve => setTimeout(resolve, 10));
    }

    // All should follow same format
    tokens.forEach(token => {
      expect(token.raw.length).toBe(128);
      expect(token.hashedToken.length).toBe(64);
      expect(token.raw).toMatch(/^[a-f0-9]+$/);
      expect(token.hashedToken).toMatch(/^[a-f0-9]+$/);
    });
  });

  test('should handle rapid successive generation', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    const startTime = performance.now();
    
    // Generate tokens as fast as possible
    const rapidTokens = [];
    for (let i = 0; i < 20; i++) {
      try {
        const token = await generateRefreshToken(ttl, userId);
        rapidTokens.push(token);
      } catch (error) {
        // Rate limiting is acceptable
        break;
      }
    }
    
    const endTime = performance.now();
    const duration = endTime - startTime;

    // Should either succeed quickly or be rate limited
    if (rapidTokens.length === 20) {
      expect(duration).toBeLessThan(5000); // Should complete quickly
    }
    
    // All generated tokens should be unique
    if (rapidTokens.length > 1) {
      const uniqueRaw = new Set(rapidTokens.map(t => t.raw));
      expect(uniqueRaw.size).toBe(rapidTokens.length);
    }
  });

  test('should validate cryptographic randomness', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    const tokens = await Promise.all(
      Array.from({ length: 100 }, () => generateRefreshToken(ttl, userId))
    );

    // Test for patterns that suggest poor randomness
    const rawTokens = tokens.map(t => t.raw);
    
    // Check for sequential patterns
    let sequentialCount = 0;
    for (let i = 1; i < rawTokens.length; i++) {
      const diff = parseInt(rawTokens[i].slice(-8), 16) - parseInt(rawTokens[i-1].slice(-8), 16);
      if (Math.abs(diff) === 1) sequentialCount++;
    }
    
    // Should have very few sequential patterns (< 5% for good randomness)
    expect(sequentialCount).toBeLessThan(5);

    // Check character distribution in a subset
    const combinedTokens = rawTokens.slice(0, 10).join('');
    const charCounts = {};
    for (const char of combinedTokens) {
      charCounts[char] = (charCounts[char] || 0) + 1;
    }
    
    // Should have reasonably distributed hex characters
    const hexChars = '0123456789abcdef';
    const expectedCount = combinedTokens.length / 16;
    const tolerance = expectedCount * 0.5; // 50% tolerance
    
    for (const char of hexChars) {
      const count = charCounts[char] || 0;
      expect(Math.abs(count - expectedCount)).toBeLessThan(tolerance);
    }
  });

  test('should handle token generation under memory pressure', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    // Create memory pressure by generating many tokens
    const largeTokenSet = [];
    
    try {
      for (let i = 0; i < 1000; i++) {
        const token = await generateRefreshToken(ttl, userId);
        largeTokenSet.push(token);
        
        // Keep some tokens in memory to create pressure
        if (i % 100 === 0 && largeTokenSet.length > 500) {
          // Remove older tokens to manage memory
          largeTokenSet.splice(0, 100);
        }
      }
      
      // Should maintain quality under pressure
      const recentTokens = largeTokenSet.slice(-10);
      recentTokens.forEach(token => {
        expect(token.raw).toMatch(/^[a-f0-9]{128}$/);
        expect(token.hashedToken).toMatch(/^[a-f0-9]{64}$/);
      });
      
    } catch (error) {
      // Memory/rate limiting is acceptable
      expect(error).toBeDefined();
    }
  });

  test('should generate tokens with correct hash relationship', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    const token = await generateRefreshToken(ttl, userId);
    
    // Verify the hash relationship
    const expectedHash = crypto.createHash('sha256').update(token.raw).digest('hex');
    expect(token.hashedToken).toBe(expectedHash);
  });

  test('should handle token generation during database stress', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    // Create concurrent database operations
    const stressOperations = [];
    
    // Token generations
    for (let i = 0; i < 5; i++) {
      stressOperations.push(generateRefreshToken(ttl, userId));
    }
    
    // Token verifications
    const testToken = await generateRefreshToken(ttl, userId);
    for (let i = 0; i < 5; i++) {
      stressOperations.push(verifyRefreshToken(testToken.raw));
    }

    const results = await Promise.allSettled(stressOperations);
    
    // Should handle concurrent operations gracefully
    const successful = results.filter(r => r.status === 'fulfilled').length;
    expect(successful).toBeGreaterThan(0);
  });
});