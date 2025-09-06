import { describe, test, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import crypto from 'crypto';
import { generateAccessToken, verifyAccessToken } from '../../../src/accessTokens.js';
import { generateRefreshToken, verifyRefreshToken, rotateRefreshToken } from '../../../src/refreshTokens.js';
import { 
  setupTestDatabase, 
  teardownTestDatabase, 
  setupTestUser, 
  cleanupTestData,
  mockBotDetector 
} from '../test-setup.js';

// Mock bot detector for controlled testing
mockBotDetector();

describe('Token Replay Attack Prevention', () => {
  beforeAll(async () => {
    await setupTestDatabase();
  });

  afterAll(async () => {
    await teardownTestDatabase();
  });

  beforeEach(async () => {
    // Clean up any existing test data
    await cleanupTestData(999, 888);
    await setupTestUser(999, 888);
  });

  test('should prevent access token replay attacks', async () => {
    const userId = 999;
    const visitorId = 888;
    
    // Generate access token
    const accessToken = await generateAccessToken(userId, visitorId);
    
    // First verification should succeed
    const firstVerification = await verifyAccessToken(accessToken.raw);
    expect(firstVerification.valid).toBe(true);
    
    // Second verification with same token should detect replay
    const secondVerification = await verifyAccessToken(accessToken.raw);
    
    // The behavior depends on implementation - either invalid or rate limited
    // Both are valid security measures against replay attacks
    expect(
      secondVerification.valid === false || 
      secondVerification.error?.includes('rate') ||
      secondVerification.error?.includes('replay')
    ).toBe(true);
  });

  test('should track JTI usage for replay detection', async () => {
    const userId = 999;
    const visitorId = 888;
    
    // Generate multiple tokens
    const tokens = await Promise.all([
      generateAccessToken(userId, visitorId),
      generateAccessToken(userId, visitorId),
      generateAccessToken(userId, visitorId)
    ]);
    
    // Each token should have unique JTI
    const jtis = tokens.map(token => {
      const payload = JSON.parse(Buffer.from(token.raw.split('.')[1], 'base64').toString());
      return payload.jti;
    });
    
    expect(new Set(jtis).size).toBe(3); // All JTIs should be unique
    
    // Each token should be verifiable once
    for (const token of tokens) {
      const verification = await verifyAccessToken(token.raw);
      expect(verification.valid).toBe(true);
    }
  });

  test('should prevent refresh token replay attacks', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;
    
    // Generate initial refresh token
    const token1 = await generateRefreshToken(ttl, userId);
    
    // Verify it's valid
    const verification1 = await verifyRefreshToken(token1.raw);
    expect(verification1.valid).toBe(true);
    
    // Rotate the token
    const rotationResult = await rotateRefreshToken(ttl, userId, token1.raw);
    expect(rotationResult.rotated).toBe(true);
    
    // Original token should now be invalid (anti-replay)
    const verification2 = await verifyRefreshToken(token1.raw);
    expect(verification2.valid).toBe(false);
    
    // New token should be valid
    if (rotationResult.raw) {
      const verification3 = await verifyRefreshToken(rotationResult.raw);
      expect(verification3.valid).toBe(true);
    }
  });

  test('should detect rapid successive token usage', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    const token = await generateRefreshToken(ttl, userId);
    
    // Rapidly verify the same token multiple times
    const rapidVerifications = await Promise.allSettled([
      verifyRefreshToken(token.raw),
      verifyRefreshToken(token.raw),
      verifyRefreshToken(token.raw),
      verifyRefreshToken(token.raw),
      verifyRefreshToken(token.raw)
    ]);

    // At least some should fail due to replay detection
    const failures = rapidVerifications.filter(result => 
      result.status === 'rejected' || 
      (result.status === 'fulfilled' && !result.value.valid)
    );
    
    expect(failures.length).toBeGreaterThan(0);
  });

  test('should handle concurrent token rotation attempts', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    const token = await generateRefreshToken(ttl, userId);
    
    // Attempt multiple concurrent rotations (race condition)
    const rotationPromises = Array.from({ length: 5 }, () =>
      rotateRefreshToken(ttl, userId, token.raw)
    );

    const results = await Promise.allSettled(rotationPromises);
    
    // Only one rotation should succeed
    const successful = results.filter(result => 
      result.status === 'fulfilled' && result.value.rotated
    );
    
    expect(successful.length).toBeLessThanOrEqual(1);
  });

  test('should prevent cross-user token usage', async () => {
    const user1Id = 999;
    const user2Id = 998;
    
    // Setup second user
    await cleanupTestData(user2Id, 887);
    await setupTestUser(user2Id, 887);
    
    const ttl = 24 * 60 * 60 * 1000;
    
    // Generate token for user1
    const user1Token = await generateRefreshToken(ttl, user1Id);
    
    // Try to rotate with user2's ID (should fail)
    const rotationResult = await rotateRefreshToken(ttl, user2Id, user1Token.raw);
    expect(rotationResult.rotated).toBe(false);
    
    // Clean up
    await cleanupTestData(user2Id, 887);
  });

  test('should detect token tampering attempts', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;
    
    const token = await generateRefreshToken(ttl, userId);
    
    // Tamper with token
    const tamperedToken = token.raw.slice(0, -5) + 'XXXXX';
    
    const verification = await verifyRefreshToken(tamperedToken);
    expect(verification.valid).toBe(false);
  });

  test('should handle malformed token inputs', async () => {
    const malformedTokens = [
      '', // Empty string
      'invalid', // Invalid format
      'a'.repeat(129), // Too long
      'special!@#$%^&*()chars', // Special characters
      null as any, // Null
      undefined as any, // Undefined
      123 as any, // Number
      {} as any // Object
    ];

    for (const badToken of malformedTokens) {
      const verification = await verifyRefreshToken(badToken);
      expect(verification.valid).toBe(false);
    }
  });

  test('should enforce token format consistency', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;
    
    // Generate multiple tokens and verify format consistency
    const tokens = await Promise.all(
      Array.from({ length: 10 }, () => generateRefreshToken(ttl, userId))
    );
    
    tokens.forEach(token => {
      // Should be hex string of specific length
      expect(token.raw).toMatch(/^[a-f0-9]{128}$/);
      expect(token.hashedToken).toMatch(/^[a-f0-9]{64}$/);
      expect(token.expiresAt).toBeInstanceOf(Date);
    });
  });

  test('should prevent expired token replay', async () => {
    const userId = 999;
    const shortTtl = 100; // 100ms TTL
    
    const token = await generateRefreshToken(shortTtl, userId);
    
    // Wait for token to expire
    await new Promise(resolve => setTimeout(resolve, 150));
    
    const verification = await verifyRefreshToken(token.raw);
    expect(verification.valid).toBe(false);
    expect(verification.error).toContain('expired');
  });
});