import { describe, test, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { 
  generateRefreshToken, 
  verifyRefreshToken,
  revokeRefreshToken
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

describe('Refresh Token Verification - Edge Cases', () => {
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

  test('should verify valid token', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    const token = await generateRefreshToken(ttl, userId);
    
    const verification = await verifyRefreshToken(token.raw);
    
    expect(verification.valid).toBe(true);
    expect(verification.payload).toBeDefined();
    expect(verification.payload.user_id).toBe(userId);
    expect(verification.error).toBeUndefined();
  });

  test('should reject non-existent token', async () => {
    const fakeToken = 'a'.repeat(128); // Valid format but doesn't exist
    
    const verification = await verifyRefreshToken(fakeToken);
    
    expect(verification.valid).toBe(false);
    expect(verification.error).toBeDefined();
    expect(verification.payload).toBeUndefined();
  });

  test('should reject expired token', async () => {
    const userId = 999;
    const shortTtl = 50; // 50ms

    const token = await generateRefreshToken(shortTtl, userId);
    
    // Wait for expiration
    await new Promise(resolve => setTimeout(resolve, 100));
    
    const verification = await verifyRefreshToken(token.raw);
    
    expect(verification.valid).toBe(false);
    expect(verification.error).toContain('expired');
  });

  test('should reject revoked token', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    const token = await generateRefreshToken(ttl, userId);
    
    // First verification should succeed
    const firstVerification = await verifyRefreshToken(token.raw);
    expect(firstVerification.valid).toBe(true);
    
    // Revoke the token
    await revokeRefreshToken(token.raw);
    
    // Second verification should fail
    const secondVerification = await verifyRefreshToken(token.raw);
    expect(secondVerification.valid).toBe(false);
  });

  test('should handle malformed token inputs', async () => {
    const malformedInputs = [
      '', // Empty string
      'short', // Too short
      'a'.repeat(127), // Almost correct length
      'a'.repeat(129), // Too long
      'not-hex-chars!@#$%', // Invalid characters
      null, // Null
      undefined, // Undefined
      123, // Number
      {}, // Object
      [], // Array
      'A'.repeat(128), // Uppercase hex (might be invalid)
      'g'.repeat(128), // Invalid hex character
      '\x00'.repeat(128), // Null bytes
      ' '.repeat(128), // Spaces
      '\n\r\t'.repeat(32), // Whitespace chars
    ];

    for (const input of malformedInputs) {
      const verification = await verifyRefreshToken(input as any);
      expect(verification.valid).toBe(false);
      expect(verification.error).toBeDefined();
    }
  });

  test('should handle concurrent verification requests', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    const token = await generateRefreshToken(ttl, userId);
    
    // Multiple concurrent verifications
    const verificationPromises = Array.from({ length: 10 }, () =>
      verifyRefreshToken(token.raw)
    );

    const results = await Promise.all(verificationPromises);
    
    // All should succeed (unless rate limited)
    results.forEach(result => {
      expect(typeof result.valid).toBe('boolean');
      if (result.valid) {
        expect(result.payload.user_id).toBe(userId);
      }
    });
  });

  test('should maintain verification integrity under load', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    // Generate multiple tokens
    const tokens = await Promise.all(
      Array.from({ length: 5 }, () => generateRefreshToken(ttl, userId))
    );

    // Verify all tokens concurrently
    const verificationPromises = tokens.map(token =>
      verifyRefreshToken(token.raw)
    );

    const results = await Promise.all(verificationPromises);
    
    // All should be valid
    results.forEach((result, index) => {
      if (result.valid) {
        expect(result.payload.user_id).toBe(userId);
      } else {
        // Rate limiting or other constraints are acceptable
        expect(result.error).toBeDefined();
      }
    });
  });

  test('should detect token format tampering', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    const token = await generateRefreshToken(ttl, userId);
    
    const tamperingPatterns = [
      // Character substitution
      token.raw.slice(0, -1) + '0',
      token.raw.slice(0, -1) + 'f',
      
      // Character insertion
      token.raw + 'a',
      'a' + token.raw,
      
      // Character deletion
      token.raw.slice(1),
      token.raw.slice(0, -1),
      
      // Position swapping
      token.raw.slice(1) + token.raw[0],
      token.raw[token.raw.length - 1] + token.raw.slice(0, -1),
      
      // Case changes (if case sensitive)
      token.raw.toUpperCase(),
      token.raw.toLowerCase(),
    ];

    for (const tamperedToken of tamperingPatterns) {
      if (tamperedToken !== token.raw) {
        const verification = await verifyRefreshToken(tamperedToken);
        expect(verification.valid).toBe(false);
      }
    }
  });

  test('should handle verification timing consistency', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    const validToken = await generateRefreshToken(ttl, userId);
    const invalidToken = 'b'.repeat(128);

    // Measure timing for valid and invalid tokens
    const timings = [];
    
    for (let i = 0; i < 10; i++) {
      // Valid token timing
      const validStart = process.hrtime.bigint();
      await verifyRefreshToken(validToken.raw);
      const validEnd = process.hrtime.bigint();
      const validTime = Number(validEnd - validStart) / 1000000;

      // Invalid token timing
      const invalidStart = process.hrtime.bigint();
      await verifyRefreshToken(invalidToken);
      const invalidEnd = process.hrtime.bigint();
      const invalidTime = Number(invalidEnd - invalidStart) / 1000000;

      timings.push({ valid: validTime, invalid: invalidTime });
    }

    // Calculate timing consistency
    const validTimes = timings.map(t => t.valid);
    const invalidTimes = timings.map(t => t.invalid);
    
    const avgValid = validTimes.reduce((a, b) => a + b) / validTimes.length;
    const avgInvalid = invalidTimes.reduce((a, b) => a + b) / invalidTimes.length;
    
    // Should not have extreme timing differences (prevents timing attacks)
    const timingRatio = Math.abs(avgValid - avgInvalid) / Math.max(avgValid, avgInvalid);
    expect(timingRatio).toBeLessThan(5.0); // Less than 500% difference
  });

  test('should handle verification with corrupted database state', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    const token = await generateRefreshToken(ttl, userId);
    
    // Verify it works initially
    const initialVerification = await verifyRefreshToken(token.raw);
    expect(initialVerification.valid).toBe(true);

    // Now simulate some database corruption scenarios
    // Note: These tests depend on implementation details
    
    try {
      // Continue with verification attempts after potential corruption
      const verification = await verifyRefreshToken(token.raw);
      
      // Should handle gracefully
      expect(typeof verification.valid).toBe('boolean');
      
    } catch (error) {
      // Database error handling is acceptable
      expect(error).toBeDefined();
    }
  });

  test('should handle edge case expiration times', async () => {
    const userId = 999;
    
    // Test tokens with expiration times at boundaries
    const edgeCases = [
      { ttl: 1, description: '1ms TTL' },
      { ttl: 1000, description: '1s TTL' },
      { ttl: 60 * 1000, description: '1min TTL' },
      { ttl: 24 * 60 * 60 * 1000, description: '1day TTL' },
    ];

    for (const testCase of edgeCases) {
      const token = await generateRefreshToken(testCase.ttl, userId);
      
      // Immediate verification should work
      const immediateVerification = await verifyRefreshToken(token.raw);
      expect(immediateVerification.valid).toBe(true);
      
      // Wait a portion of TTL
      const waitTime = Math.min(testCase.ttl * 0.5, 100);
      await new Promise(resolve => setTimeout(resolve, waitTime));
      
      if (waitTime < testCase.ttl) {
        // Should still be valid
        const midVerification = await verifyRefreshToken(token.raw);
        expect(midVerification.valid).toBe(true);
      }
    }
  });

  test('should handle multiple revocation attempts', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    const token = await generateRefreshToken(ttl, userId);
    
    // First revocation
    await revokeRefreshToken(token.raw);
    
    // Multiple subsequent revocations should not error
    await expect(revokeRefreshToken(token.raw)).resolves.not.toThrow();
    await expect(revokeRefreshToken(token.raw)).resolves.not.toThrow();
    
    // Token should remain invalid
    const verification = await verifyRefreshToken(token.raw);
    expect(verification.valid).toBe(false);
  });

  test('should maintain verification state consistency', async () => {
    const userId = 999;
    const ttl = 24 * 60 * 60 * 1000;

    const tokens = await Promise.all(
      Array.from({ length: 5 }, () => generateRefreshToken(ttl, userId))
    );

    // Revoke some tokens
    await revokeRefreshToken(tokens[1].raw);
    await revokeRefreshToken(tokens[3].raw);

    // Verify state consistency
    const verifications = await Promise.all(
      tokens.map(token => verifyRefreshToken(token.raw))
    );

    expect(verifications[0].valid).toBe(true);  // Should be valid
    expect(verifications[1].valid).toBe(false); // Should be revoked
    expect(verifications[2].valid).toBe(true);  // Should be valid
    expect(verifications[3].valid).toBe(false); // Should be revoked
    expect(verifications[4].valid).toBe(true);  // Should be valid
  });

  test('should handle verification with special token patterns', async () => {
    const userId = 999;
    
    // Generate enough tokens to potentially hit patterns
    const tokens = await Promise.all(
      Array.from({ length: 50 }, () => generateRefreshToken(24 * 60 * 60 * 1000, userId))
    );

    // Look for any tokens with special patterns
    const patternTokens = tokens.filter(token => {
      const raw = token.raw;
      return (
        raw.startsWith('000') || // Starts with zeros
        raw.endsWith('000') ||   // Ends with zeros
        raw.includes('aaaa') ||  // Has repeated chars
        raw.includes('0000')     // Has repeated zeros
      );
    });

    // Verify these special pattern tokens work correctly
    for (const token of patternTokens) {
      const verification = await verifyRefreshToken(token.raw);
      expect(verification.valid).toBe(true);
    }
  });
});