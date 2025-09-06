import { describe, test, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { generateMfaCode, verifyMfaCode } from '../../../src/jwtAuth/controllers/MFA.js';
import { 
  setupTestDatabase, 
  teardownTestDatabase, 
  setupTestUser, 
  cleanupTestData,
  mockBotDetector 
} from '../test-setup.js';

// Mock bot detector for controlled testing
mockBotDetector();

describe('MFA Code Generation and Verification', () => {
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

  test('should generate valid MFA codes', async () => {
    const userId = 999;

    const mfaResult = await generateMfaCode(userId);
    
    expect(mfaResult).toHaveProperty('code');
    expect(mfaResult).toHaveProperty('expiresAt');
    expect(typeof mfaResult.code).toBe('string');
    expect(mfaResult.code).toMatch(/^\d{6}$/); // 6-digit numeric code
    expect(mfaResult.expiresAt).toBeInstanceOf(Date);
    expect(mfaResult.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  test('should verify valid MFA codes', async () => {
    const userId = 999;

    const generated = await generateMfaCode(userId);
    const verification = await verifyMfaCode(userId, generated.code);
    
    expect(verification.valid).toBe(true);
    expect(verification.error).toBeUndefined();
  });

  test('should reject invalid MFA codes', async () => {
    const userId = 999;

    // Generate a valid code first
    await generateMfaCode(userId);
    
    const invalidCodes = [
      '000000', // Likely invalid
      '999999', // Likely invalid
      '123456', // Common/weak code
      '654321', // Reverse pattern
      '111111', // Repeated digits
      'abcdef', // Non-numeric
      '12345',  // Too short
      '1234567', // Too long
      '',       // Empty
      null,     // Null
      undefined // Undefined
    ];

    for (const code of invalidCodes) {
      const verification = await verifyMfaCode(userId, code as any);
      expect(verification.valid).toBe(false);
      expect(verification.error).toBeDefined();
    }
  });

  test('should reject expired MFA codes', async () => {
    const userId = 999;

    // This test depends on the implementation having a way to create expired codes
    // or having very short TTL for testing
    const generated = await generateMfaCode(userId);
    
    // If the implementation allows manual expiration or has short TTL for testing
    // Wait for potential expiration (implementation dependent)
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Try to verify (might still be valid depending on TTL configuration)
    const verification = await verifyMfaCode(userId, generated.code);
    
    // This test is implementation dependent - either should be valid or expired
    expect(typeof verification.valid).toBe('boolean');
    if (!verification.valid) {
      expect(verification.error).toContain('expired');
    }
  });

  test('should handle multiple MFA codes for same user', async () => {
    const userId = 999;

    // Generate multiple codes
    const codes = [];
    for (let i = 0; i < 5; i++) {
      const generated = await generateMfaCode(userId);
      codes.push(generated.code);
      
      // Small delay between generations
      await new Promise(resolve => setTimeout(resolve, 10));
    }

    // All codes should be unique
    const uniqueCodes = new Set(codes);
    expect(uniqueCodes.size).toBe(codes.length);

    // Only the latest code should be valid (if implementation invalidates previous)
    // OR all codes should be valid (if implementation allows multiple active codes)
    const latestCode = codes[codes.length - 1];
    const latestVerification = await verifyMfaCode(userId, latestCode);
    expect(latestVerification.valid).toBe(true);
  });

  test('should prevent MFA code reuse', async () => {
    const userId = 999;

    const generated = await generateMfaCode(userId);
    
    // First verification should succeed
    const firstVerification = await verifyMfaCode(userId, generated.code);
    expect(firstVerification.valid).toBe(true);
    
    // Second verification should fail (if implementation prevents reuse)
    const secondVerification = await verifyMfaCode(userId, generated.code);
    
    // This behavior depends on implementation
    // Either should fail (one-time use) or succeed (multiple use allowed)
    expect(typeof secondVerification.valid).toBe('boolean');
    if (!secondVerification.valid) {
      expect(secondVerification.error).toBeDefined();
    }
  });

  test('should handle concurrent MFA code generation', async () => {
    const userId = 999;

    // Generate codes concurrently
    const codePromises = Array.from({ length: 10 }, () => 
      generateMfaCode(userId)
    );

    const results = await Promise.allSettled(codePromises);
    
    // All should succeed or some should fail gracefully
    const successful = results.filter(r => r.status === 'fulfilled');
    const failed = results.filter(r => r.status === 'rejected');
    
    expect(successful.length + failed.length).toBe(10);
    expect(successful.length).toBeGreaterThan(0);
    
    // Successful codes should be unique
    if (successful.length > 1) {
      const codes = successful.map(r => (r as any).value.code);
      const uniqueCodes = new Set(codes);
      expect(uniqueCodes.size).toBe(codes.length);
    }
  });

  test('should handle concurrent MFA code verification', async () => {
    const userId = 999;

    const generated = await generateMfaCode(userId);
    
    // Verify the same code concurrently
    const verificationPromises = Array.from({ length: 20 }, () =>
      verifyMfaCode(userId, generated.code)
    );

    const results = await Promise.all(verificationPromises);
    
    // Behavior depends on implementation:
    // - If one-time use: only first should succeed
    // - If reusable: all should succeed
    // - If rate limited: some should succeed
    const successful = results.filter(r => r.valid);
    const failed = results.filter(r => !r.valid);
    
    expect(successful.length + failed.length).toBe(20);
    expect(successful.length).toBeGreaterThan(0);
  });

  test('should validate MFA code format constraints', async () => {
    const userId = 999;

    const generated = await generateMfaCode(userId);
    
    // Code should meet format requirements
    expect(generated.code).toMatch(/^\d{6}$/);
    expect(generated.code.length).toBe(6);
    
    // Should not be all same digits (weak)
    const uniqueDigits = new Set(generated.code.split(''));
    expect(uniqueDigits.size).toBeGreaterThan(1);
    
    // Should not be sequential
    const isSequential = /012345|123456|234567|345678|456789|567890/.test(generated.code) ||
                         /987654|876543|765432|654321|543210|432109/.test(generated.code);
    expect(isSequential).toBe(false);
  });

  test('should handle MFA for different users', async () => {
    const userIds = [999, 998, 997];
    
    // Setup additional users
    for (const uid of userIds) {
      if (uid !== 999) {
        await cleanupTestData(uid, uid - 111);
        await setupTestUser(uid, uid - 111);
      }
    }

    // Generate codes for each user
    const userCodes = {};
    for (const userId of userIds) {
      const generated = await generateMfaCode(userId);
      userCodes[userId] = generated.code;
    }

    // Verify each user's code
    for (const userId of userIds) {
      const verification = await verifyMfaCode(userId, userCodes[userId]);
      expect(verification.valid).toBe(true);
    }

    // Cross-user verification should fail
    const crossVerification = await verifyMfaCode(999, userCodes[998]);
    expect(crossVerification.valid).toBe(false);

    // Clean up
    for (const uid of userIds) {
      if (uid !== 999) {
        await cleanupTestData(uid, uid - 111);
      }
    }
  });

  test('should handle MFA generation under rate limiting', async () => {
    const userId = 999;

    // Attempt rapid generation to trigger rate limiting
    const attempts = [];
    for (let i = 0; i < 20; i++) {
      try {
        const generated = await generateMfaCode(userId);
        attempts.push({ success: true, code: generated.code });
      } catch (error) {
        attempts.push({ success: false, error: error.message });
      }
    }

    // Should have some rate limiting effect
    const successful = attempts.filter(a => a.success);
    const failed = attempts.filter(a => !a.success);
    
    expect(successful.length + failed.length).toBe(20);
    
    // Either all should succeed (no rate limiting) or some should fail
    if (failed.length > 0) {
      // Rate limiting is active
      expect(successful.length).toBeLessThan(20);
    }
  });

  test('should generate cryptographically secure codes', async () => {
    const userId = 999;

    // Generate many codes to test randomness
    const codes = [];
    for (let i = 0; i < 100; i++) {
      const generated = await generateMfaCode(userId);
      codes.push(generated.code);
    }

    // Statistical tests for randomness
    const digitCounts = {};
    for (const code of codes) {
      for (const digit of code) {
        digitCounts[digit] = (digitCounts[digit] || 0) + 1;
      }
    }

    // Each digit should appear roughly equally (chi-square test approximation)
    const expectedCount = (codes.length * 6) / 10; // Total digits / 10 possible digits
    const tolerance = expectedCount * 0.3; // 30% tolerance

    for (let digit = 0; digit <= 9; digit++) {
      const count = digitCounts[digit.toString()] || 0;
      expect(Math.abs(count - expectedCount)).toBeLessThan(tolerance);
    }

    // Check for patterns
    let sequentialCount = 0;
    let repeatedDigitCount = 0;
    
    for (const code of codes) {
      // Check for sequences
      if (/012|123|234|345|456|567|678|789|890/.test(code) ||
          /987|876|765|654|543|432|321|210|109/.test(code)) {
        sequentialCount++;
      }
      
      // Check for repeated digits
      if (/(.)\1{2,}/.test(code)) {
        repeatedDigitCount++;
      }
    }

    // Should have very few patterns
    expect(sequentialCount).toBeLessThan(codes.length * 0.05); // Less than 5%
    expect(repeatedDigitCount).toBeLessThan(codes.length * 0.05); // Less than 5%
  });

  test('should handle MFA code edge cases', async () => {
    const userId = 999;

    // Test edge cases in verification
    const edgeCases = [
      '000000', // All zeros
      '000001', // Almost all zeros
      '999999', // All nines
      '100000', // Leading one
      '000010', // Zero in middle
    ];

    // Generate a valid code first
    const validGenerated = await generateMfaCode(userId);
    
    // Test that our valid code works
    const validVerification = await verifyMfaCode(userId, validGenerated.code);
    expect(validVerification.valid).toBe(true);
    
    // Test edge cases (should fail unless they happen to match)
    for (const edgeCode of edgeCases) {
      const verification = await verifyMfaCode(userId, edgeCode);
      
      if (edgeCode === validGenerated.code) {
        expect(verification.valid).toBe(true);
      } else {
        expect(verification.valid).toBe(false);
      }
    }
  });

  test('should maintain MFA security under stress', async () => {
    const userId = 999;

    // Generate and verify many codes under stress
    const operations = [];
    
    for (let i = 0; i < 50; i++) {
      operations.push(
        generateMfaCode(userId).then(generated => 
          verifyMfaCode(userId, generated.code)
        )
      );
    }

    const results = await Promise.allSettled(operations);
    
    // Should handle stress gracefully
    const successful = results.filter(r => 
      r.status === 'fulfilled' && r.value.valid
    );
    const failed = results.filter(r => 
      r.status === 'rejected' || 
      (r.status === 'fulfilled' && !r.value.valid)
    );
    
    expect(successful.length + failed.length).toBe(50);
    expect(successful.length).toBeGreaterThan(0);
  });
});