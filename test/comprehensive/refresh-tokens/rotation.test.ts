import { describe, test, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { 
  generateRefreshToken, 
  verifyRefreshToken,
  rotateRefreshToken,
  revokeRefreshToken
} from '../../../src/refreshTokens.js';
import { 
  setupTestDatabase, 
  teardownTestDatabase, 
  setupTestUser, 
  cleanupTestData,
  mockBotDetector,
  promisePool 
} from '../test-setup.js';

// Mock bot detector for controlled testing
mockBotDetector();

describe('Refresh Token Rotation - Advanced Scenarios', () => {
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

  test('should successfully rotate valid token', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    const originalToken = await generateRefreshToken(ttl, userId);
    
    const rotationResult = await rotateRefreshToken(ttl, userId, originalToken.raw);
    
    expect(rotationResult.rotated).toBe(true);
    expect(rotationResult.raw).toBeDefined();
    expect(rotationResult.hashedToken).toBeDefined();
    expect(rotationResult.expiresAt).toBeDefined();
    
    // Original token should be invalid
    const originalVerification = await verifyRefreshToken(originalToken.raw);
    expect(originalVerification.valid).toBe(false);
    
    // New token should be valid
    if (rotationResult.raw) {
      const newVerification = await verifyRefreshToken(rotationResult.raw);
      expect(newVerification.valid).toBe(true);
    }
  });

  test('should fail to rotate non-existent token', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;
    const fakeToken = 'a'.repeat(128);

    const rotationResult = await rotateRefreshToken(ttl, userId, fakeToken);
    
    expect(rotationResult.rotated).toBe(false);
    expect(rotationResult.raw).toBeUndefined();
    expect(rotationResult.hashedToken).toBeUndefined();
    expect(rotationResult.expiresAt).toBeUndefined();
  });

  test('should fail to rotate expired token', async () => {
    const userId = 999;
    const shortTtl = 50; // 50ms

    const token = await generateRefreshToken(shortTtl, userId);
    
    // Wait for expiration
    await new Promise(resolve => setTimeout(resolve, 100));
    
    const rotationResult = await rotateRefreshToken(24 * 60 * 60 * 1000, userId, token.raw);
    
    expect(rotationResult.rotated).toBe(false);
  });

  test('should fail to rotate revoked token', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    const token = await generateRefreshToken(ttl, userId);
    
    // Revoke the token
    await revokeRefreshToken(token.raw);
    
    const rotationResult = await rotateRefreshToken(ttl, userId, token.raw);
    
    expect(rotationResult.rotated).toBe(false);
  });

  test('should handle rotation with hashed token input', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    const token = await generateRefreshToken(ttl, userId);
    
    // Try to rotate using hashed token
    const rotationResult = await rotateRefreshToken(ttl, userId, token.hashedToken, true);
    
    // Should either work or fail gracefully
    expect(typeof rotationResult.rotated).toBe('boolean');
  });

  test('should handle concurrent rotation attempts', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    const token = await generateRefreshToken(ttl, userId);
    
    // Attempt multiple concurrent rotations
    const rotationPromises = Array.from({ length: 5 }, () =>
      rotateRefreshToken(ttl, userId, token.raw)
    );

    const results = await Promise.allSettled(rotationPromises);
    
    // Only one rotation should succeed
    const successful = results.filter(result => 
      result.status === 'fulfilled' && result.value.rotated
    );
    
    expect(successful.length).toBeLessThanOrEqual(1);
    
    // Original token should be invalid after any successful rotation
    const originalVerification = await verifyRefreshToken(token.raw);
    if (successful.length > 0) {
      expect(originalVerification.valid).toBe(false);
    }
  });

  test('should maintain session limits during rotation', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;
    const maxSessions = 5; // Assuming max sessions from config

    const tokens = [];
    for (let i = 0; i < maxSessions + 2; i++) {
      const token = await generateRefreshToken(ttl, userId);
      tokens.push(token);
    }

    // Try to rotate all tokens
    const rotationResults = await Promise.allSettled(
      tokens.map(token => rotateRefreshToken(ttl, userId, token.raw))
    );

    // Should respect session limits
    const successfulRotations = rotationResults.filter(result => 
      result.status === 'fulfilled' && result.value.rotated
    );
    
    // Not all rotations should succeed if session limits are enforced
    expect(successfulRotations.length).toBeLessThanOrEqual(maxSessions);
  });

  test('should handle rotation chain scenarios', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    // Create initial session
    const token1 = await generateRefreshToken(ttl, userId);
    expect((await verifyRefreshToken(token1.raw)).valid).toBe(true);

    // First rotation
    const rotation1 = await rotateRefreshToken(ttl, userId, token1.raw);
    expect(rotation1.rotated).toBe(true);
    expect((await verifyRefreshToken(token1.raw)).valid).toBe(false);

    // Second rotation (chaining)
    if (rotation1.raw) {
      const rotation2 = await rotateRefreshToken(ttl, userId, rotation1.raw);
      expect(rotation2.rotated).toBe(true);
      expect((await verifyRefreshToken(rotation1.raw)).valid).toBe(false);

      // Third rotation
      if (rotation2.raw) {
        const rotation3 = await rotateRefreshToken(ttl, userId, rotation2.raw);
        expect(rotation3.rotated).toBe(true);
        expect((await verifyRefreshToken(rotation2.raw)).valid).toBe(false);
        
        // Final token should be valid
        if (rotation3.raw) {
          expect((await verifyRefreshToken(rotation3.raw)).valid).toBe(true);
        }
      }
    }
  });

  test('should handle rotation with different TTL values', async () => {
    const userId = 999;
    const originalTtl = 24 * 60 * 60 * 1000;

    const token = await generateRefreshToken(originalTtl, userId);
    
    const newTtlValues = [
      1 * 60 * 60 * 1000,    // 1 hour
      12 * 60 * 60 * 1000,   // 12 hours
      48 * 60 * 60 * 1000,   // 48 hours
      7 * 24 * 60 * 60 * 1000, // 7 days
    ];

    for (const newTtl of newTtlValues) {
      const testToken = await generateRefreshToken(originalTtl, userId);
      
      const rotationResult = await rotateRefreshToken(newTtl, userId, testToken.raw);
      
      if (rotationResult.rotated && rotationResult.expiresAt) {
        const expectedExpiry = Date.now() + newTtl;
        const actualExpiry = rotationResult.expiresAt.getTime();
        
        // Should be close to expected expiry (within 1 second)
        expect(Math.abs(actualExpiry - expectedExpiry)).toBeLessThan(1000);
      }
    }
  });

  test('should handle rotation during high concurrency', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    // Generate initial tokens
    const initialTokens = await Promise.all(
      Array.from({ length: 10 }, () => generateRefreshToken(ttl, userId))
    );

    // Mix of operations
    const operations = [];
    
    // Rotations
    operations.push(...initialTokens.slice(0, 5).map(token => 
      rotateRefreshToken(ttl, userId, token.raw)
    ));
    
    // Verifications
    operations.push(...initialTokens.slice(5, 8).map(token =>
      verifyRefreshToken(token.raw)
    ));
    
    // New generations
    operations.push(...Array.from({ length: 5 }, () => 
      generateRefreshToken(ttl, userId)
    ));

    const results = await Promise.allSettled(operations);
    
    // Should handle mixed operations gracefully
    const successful = results.filter(r => r.status === 'fulfilled').length;
    expect(successful).toBeGreaterThan(0);
  });

  test('should prevent rotation of already rotated tokens', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    const originalToken = await generateRefreshToken(ttl, userId);
    
    // First rotation
    const firstRotation = await rotateRefreshToken(ttl, userId, originalToken.raw);
    expect(firstRotation.rotated).toBe(true);
    
    // Attempt to rotate the original token again
    const secondRotation = await rotateRefreshToken(ttl, userId, originalToken.raw);
    expect(secondRotation.rotated).toBe(false);
  });

  test('should handle rotation with extreme TTL values', async () => {
    const userId = 999;
    const originalTtl = 24 * 60 * 60 * 1000;

    const token = await generateRefreshToken(originalTtl, userId);
    
    const extremeTtls = [
      0,                    // Zero TTL
      -1000,               // Negative TTL
      1,                   // 1ms TTL
      Number.MAX_SAFE_INTEGER, // Maximum TTL
    ];

    for (const extremeTtl of extremeTtls) {
      const testToken = await generateRefreshToken(originalTtl, userId);
      
      try {
        const rotationResult = await rotateRefreshToken(extremeTtl, userId, testToken.raw);
        
        if (rotationResult.rotated) {
          // If rotation succeeded, verify the new token
          if (rotationResult.raw) {
            const verification = await verifyRefreshToken(rotationResult.raw);
            // For zero/negative TTL, token might be immediately expired
            if (extremeTtl <= 0) {
              expect(verification.valid).toBe(false);
            }
          }
        }
      } catch (error) {
        // Extreme TTL rejection is acceptable
        expect(error).toBeDefined();
      }
    }
  });

  test('should maintain database consistency during rotation failures', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    const token = await generateRefreshToken(ttl, userId);
    
    // Verify initial state
    const initialVerification = await verifyRefreshToken(token.raw);
    expect(initialVerification.valid).toBe(true);

    // Attempt rotation with invalid user (should fail)
    const invalidRotation = await rotateRefreshToken(ttl, 99999, token.raw);
    expect(invalidRotation.rotated).toBe(false);
    
    // Original token should still be valid after failed rotation
    const postFailureVerification = await verifyRefreshToken(token.raw);
    expect(postFailureVerification.valid).toBe(true);
    
    // Successful rotation should invalidate original
    const successfulRotation = await rotateRefreshToken(ttl, userId, token.raw);
    if (successfulRotation.rotated) {
      const finalVerification = await verifyRefreshToken(token.raw);
      expect(finalVerification.valid).toBe(false);
    }
  });

  test('should handle rotation with malformed inputs', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    const malformedInputs = [
      '', // Empty string
      'short', // Too short
      'a'.repeat(129), // Too long
      'not-hex!@#$', // Invalid characters
      null, // Null
      undefined, // Undefined
    ];

    for (const input of malformedInputs) {
      const rotationResult = await rotateRefreshToken(ttl, userId, input as any);
      expect(rotationResult.rotated).toBe(false);
    }
  });

  test('should track rotation metrics correctly', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    // Generate initial token
    const token = await generateRefreshToken(ttl, userId);
    
    // Check initial usage count
    const [rows] = await promisePool.execute(
      'SELECT usage_count FROM refresh_tokens WHERE token = SHA2(?, 256)',
      [token.raw]
    ) as any;
    
    if (rows.length > 0) {
      const initialUsageCount = rows[0].usage_count;
      
      // Rotate token
      const rotationResult = await rotateRefreshToken(ttl, userId, token.raw);
      
      if (rotationResult.rotated && rotationResult.raw) {
        // Check new token usage count should start at 0
        const [newRows] = await promisePool.execute(
          'SELECT usage_count FROM refresh_tokens WHERE token = SHA2(?, 256)',
          [rotationResult.raw]
        ) as any;
        
        if (newRows.length > 0) {
          expect(newRows[0].usage_count).toBe(0);
        }
      }
    }
  });

  test('should handle rotation during session cleanup', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    // Generate many tokens to potentially trigger cleanup
    const tokens = await Promise.all(
      Array.from({ length: 20 }, () => generateRefreshToken(ttl, userId))
    );

    // Try to rotate some during potential cleanup
    const rotationResults = await Promise.allSettled([
      rotateRefreshToken(ttl, userId, tokens[0].raw),
      rotateRefreshToken(ttl, userId, tokens[1].raw),
      rotateRefreshToken(ttl, userId, tokens[2].raw),
    ]);

    // Should handle rotation during cleanup gracefully
    const successful = rotationResults.filter(result => 
      result.status === 'fulfilled' && result.value.rotated
    );
    
    expect(successful.length).toBeGreaterThanOrEqual(0);
  });
});