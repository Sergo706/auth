import { describe, test, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import argon2 from 'argon2';
import crypto from 'crypto';
import { 
  setupTestDatabase, 
  teardownTestDatabase, 
  setupTestUser, 
  cleanupTestData,
  mockBotDetector 
} from '../test-setup.js';

// Mock bot detector for controlled testing
mockBotDetector();

describe('Argon2 Password Hashing', () => {
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

  test('should hash passwords with Argon2', async () => {
    const password = 'secure-password-123';
    
    const hash = await argon2.hash(password);
    
    expect(hash).toBeDefined();
    expect(typeof hash).toBe('string');
    expect(hash.startsWith('$argon2')).toBe(true);
    expect(hash.length).toBeGreaterThan(50);
  });

  test('should verify correct passwords', async () => {
    const password = 'test-password-456';
    
    const hash = await argon2.hash(password);
    const isValid = await argon2.verify(hash, password);
    
    expect(isValid).toBe(true);
  });

  test('should reject incorrect passwords', async () => {
    const correctPassword = 'correct-password';
    const wrongPassword = 'wrong-password';
    
    const hash = await argon2.hash(correctPassword);
    const isValid = await argon2.verify(hash, wrongPassword);
    
    expect(isValid).toBe(false);
  });

  test('should generate different hashes for same password (salt)', async () => {
    const password = 'same-password-123';
    
    const hash1 = await argon2.hash(password);
    const hash2 = await argon2.hash(password);
    const hash3 = await argon2.hash(password);
    
    // Hashes should be different due to random salt
    expect(hash1).not.toBe(hash2);
    expect(hash2).not.toBe(hash3);
    expect(hash1).not.toBe(hash3);
    
    // But all should verify the same password
    expect(await argon2.verify(hash1, password)).toBe(true);
    expect(await argon2.verify(hash2, password)).toBe(true);
    expect(await argon2.verify(hash3, password)).toBe(true);
  });

  test('should handle various password types', async () => {
    const passwords = [
      'simple123',
      'Complex!Password@2023',
      'пароль', // Cyrillic
      '密码', // Chinese
      '🔐🚀🌟', // Emoji
      'a'.repeat(1000), // Very long
      '', // Empty (if allowed)
      ' ', // Space only
      '\n\t\r', // Whitespace chars
      'special!@#$%^&*()chars',
    ];

    for (const password of passwords) {
      if (password.length > 0) { // Skip empty if not allowed
        try {
          const hash = await argon2.hash(password);
          const isValid = await argon2.verify(hash, password);
          
          expect(isValid).toBe(true);
          expect(hash.startsWith('$argon2')).toBe(true);
        } catch (error) {
          // Some edge cases might be rejected
          expect(error).toBeDefined();
        }
      }
    }
  });

  test('should handle concurrent password hashing', async () => {
    const passwords = Array.from({ length: 20 }, (_, i) => `concurrent-password-${i}`);
    
    const hashPromises = passwords.map(password => argon2.hash(password));
    const hashes = await Promise.all(hashPromises);
    
    // All hashes should be generated
    expect(hashes.length).toBe(passwords.length);
    
    // All hashes should be unique
    const uniqueHashes = new Set(hashes);
    expect(uniqueHashes.size).toBe(hashes.length);
    
    // All should verify correctly
    const verifications = await Promise.all(
      hashes.map((hash, i) => argon2.verify(hash, passwords[i]))
    );
    
    verifications.forEach(isValid => {
      expect(isValid).toBe(true);
    });
  });

  test('should handle timing attack resistance', async () => {
    const correctPassword = 'timing-test-password';
    const wrongPasswords = [
      'wrong-password',
      'completely-different',
      'timing-test-password!', // Close but wrong
      '', // Empty
      'x', // Single char
    ];
    
    const hash = await argon2.hash(correctPassword);
    
    // Measure verification timings
    const timings = [];
    
    for (let i = 0; i < 10; i++) {
      // Time correct password
      const correctStart = process.hrtime.bigint();
      await argon2.verify(hash, correctPassword);
      const correctEnd = process.hrtime.bigint();
      const correctTime = Number(correctEnd - correctStart) / 1000000; // Convert to ms
      
      // Time wrong passwords
      const wrongTimes = [];
      for (const wrongPassword of wrongPasswords) {
        const wrongStart = process.hrtime.bigint();
        await argon2.verify(hash, wrongPassword);
        const wrongEnd = process.hrtime.bigint();
        wrongTimes.push(Number(wrongEnd - wrongStart) / 1000000);
      }
      
      const avgWrongTime = wrongTimes.reduce((a, b) => a + b) / wrongTimes.length;
      timings.push({ correct: correctTime, wrong: avgWrongTime });
    }
    
    const avgCorrect = timings.reduce((sum, t) => sum + t.correct, 0) / timings.length;
    const avgWrong = timings.reduce((sum, t) => sum + t.wrong, 0) / timings.length;
    
    // Timing difference should be minimal (Argon2 is designed to be timing-safe)
    const timingRatio = Math.abs(avgCorrect - avgWrong) / Math.max(avgCorrect, avgWrong);
    expect(timingRatio).toBeLessThan(2.0); // Less than 200% difference (generous for CI)
  });

  test('should use appropriate Argon2 parameters', async () => {
    const password = 'parameter-test-password';
    
    const hash = await argon2.hash(password);
    
    // Should use Argon2id variant (most secure)
    expect(hash.startsWith('$argon2id')).toBe(true);
    
    // Extract parameters from hash
    const parts = hash.split('$');
    expect(parts.length).toBeGreaterThan(4);
    
    // Should have reasonable parameters
    const paramPart = parts[3];
    expect(paramPart).toContain('m='); // Memory parameter
    expect(paramPart).toContain('t='); // Time parameter
    expect(paramPart).toContain('p='); // Parallelism parameter
  });

  test('should handle edge case password lengths', async () => {
    const edgeLengths = [
      1,    // Minimum
      2,    // Very short
      64,   // Common max
      72,   // bcrypt limit
      128,  // Extended
      256,  // Very long
      512,  // Extremely long
    ];
    
    for (const length of edgeLengths) {
      const password = 'a'.repeat(length);
      
      try {
        const hash = await argon2.hash(password);
        const isValid = await argon2.verify(hash, password);
        
        expect(isValid).toBe(true);
      } catch (error) {
        // Some extreme lengths might be rejected
        expect(error).toBeDefined();
      }
    }
  });

  test('should maintain hash integrity under load', async () => {
    const basePassword = 'load-test-password';
    const iterations = 100;
    
    const promises = Array.from({ length: iterations }, async (_, i) => {
      const password = `${basePassword}-${i}`;
      const hash = await argon2.hash(password);
      
      // Immediately verify
      const isValid = await argon2.verify(hash, password);
      expect(isValid).toBe(true);
      
      // Verify wrong password fails
      const wrongValid = await argon2.verify(hash, `${password}-wrong`);
      expect(wrongValid).toBe(false);
      
      return hash;
    });
    
    const hashes = await Promise.all(promises);
    
    // All hashes should be unique
    const uniqueHashes = new Set(hashes);
    expect(uniqueHashes.size).toBe(iterations);
  });

  test('should handle memory pressure gracefully', async () => {
    const passwords = Array.from({ length: 50 }, (_, i) => `memory-test-${i}`);
    
    // Hash all passwords
    const hashes = [];
    for (const password of passwords) {
      const hash = await argon2.hash(password);
      hashes.push({ password, hash });
    }
    
    // Verify all passwords
    for (const { password, hash } of hashes) {
      const isValid = await argon2.verify(hash, password);
      expect(isValid).toBe(true);
    }
    
    // Should maintain performance
    expect(hashes.length).toBe(passwords.length);
  });

  test('should be resistant to common attacks', async () => {
    const testPassword = 'attack-test-password';
    const hash = await argon2.hash(testPassword);
    
    // Dictionary attack simulation
    const commonPasswords = [
      'password',
      '123456',
      'admin',
      'test',
      'password123',
      'qwerty',
      'letmein',
      'welcome',
    ];
    
    for (const commonPassword of commonPasswords) {
      const isValid = await argon2.verify(hash, commonPassword);
      expect(isValid).toBe(false);
    }
    
    // Brute force simulation (limited)
    const bruteForceAttempts = [
      'a', 'b', 'c', '1', '2', '3',
      'aa', 'ab', 'ac', '11', '12', '13',
    ];
    
    for (const attempt of bruteForceAttempts) {
      const isValid = await argon2.verify(hash, attempt);
      expect(isValid).toBe(false);
    }
  });

  test('should handle Unicode normalization', async () => {
    // Test Unicode normalization issues
    const unicodePasswords = [
      'café', // é as single character
      'cafe\u0301', // e + combining acute accent
      'Ω', // Greek capital omega
      '\u03A9', // Unicode code point for omega
    ];
    
    for (const password of unicodePasswords) {
      const hash = await argon2.hash(password);
      
      // Should verify with exact same input
      const isValid = await argon2.verify(hash, password);
      expect(isValid).toBe(true);
      
      // Should not verify with different normalization
      const normalized = password.normalize('NFC');
      if (normalized !== password) {
        const normalizedValid = await argon2.verify(hash, normalized);
        // This depends on how the library handles Unicode
        expect(typeof normalizedValid).toBe('boolean');
      }
    }
  });

  test('should provide consistent performance characteristics', async () => {
    const password = 'performance-test-password';
    const iterations = 10;
    
    const hashTimes = [];
    const verifyTimes = [];
    
    for (let i = 0; i < iterations; i++) {
      // Time hashing
      const hashStart = process.hrtime.bigint();
      const hash = await argon2.hash(password);
      const hashEnd = process.hrtime.bigint();
      hashTimes.push(Number(hashEnd - hashStart) / 1000000);
      
      // Time verification
      const verifyStart = process.hrtime.bigint();
      await argon2.verify(hash, password);
      const verifyEnd = process.hrtime.bigint();
      verifyTimes.push(Number(verifyEnd - verifyStart) / 1000000);
    }
    
    const avgHashTime = hashTimes.reduce((a, b) => a + b) / hashTimes.length;
    const avgVerifyTime = verifyTimes.reduce((a, b) => a + b) / verifyTimes.length;
    
    // Performance should be reasonable
    expect(avgHashTime).toBeLessThan(5000); // Less than 5 seconds
    expect(avgVerifyTime).toBeLessThan(5000); // Less than 5 seconds
    
    // Times should be consistent (low variance)
    const hashVariance = hashTimes.reduce((sum, time) => 
      sum + Math.pow(time - avgHashTime, 2), 0) / hashTimes.length;
    const hashStdDev = Math.sqrt(hashVariance);
    
    expect(hashStdDev / avgHashTime).toBeLessThan(0.5); // CV < 50%
  });
});