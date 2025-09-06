import { describe, test, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import crypto from 'crypto';
import argon2 from 'argon2';
import { 
  setupTestDatabase, 
  teardownTestDatabase, 
  setupTestUser, 
  cleanupTestData,
  mockBotDetector 
} from '../test-setup.js';

// Mock bot detector for controlled testing
mockBotDetector();

describe('SHA-256 Hashing (Token Storage)', () => {
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

  test('should generate consistent SHA-256 hashes', () => {
    const input = 'test-token-12345';
    
    // Multiple hashes of the same input should be identical
    const hash1 = crypto.createHash('sha256').update(input).digest('hex');
    const hash2 = crypto.createHash('sha256').update(input).digest('hex');
    const hash3 = crypto.createHash('sha256').update(input).digest('hex');
    
    expect(hash1).toBe(hash2);
    expect(hash2).toBe(hash3);
    expect(hash1).toMatch(/^[a-f0-9]{64}$/);
  });

  test('should generate different hashes for different inputs', () => {
    const inputs = [
      'token1',
      'token2',
      'token1 ', // With space
      'Token1', // Different case
      'token1\n', // With newline
      'oken1', // Missing first character
      'token12', // Extra character
    ];

    const hashes = inputs.map(input => 
      crypto.createHash('sha256').update(input).digest('hex')
    );

    // All hashes should be unique
    const uniqueHashes = new Set(hashes);
    expect(uniqueHashes.size).toBe(inputs.length);
    
    // All should be valid hex strings
    hashes.forEach(hash => {
      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  test('should handle binary data correctly', () => {
    const binaryData = Buffer.from([0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD]);
    
    const hash1 = crypto.createHash('sha256').update(binaryData).digest('hex');
    const hash2 = crypto.createHash('sha256').update(binaryData).digest('hex');
    
    expect(hash1).toBe(hash2);
    expect(hash1).toMatch(/^[a-f0-9]{64}$/);
  });

  test('should demonstrate avalanche effect', () => {
    const baseInput = 'avalanche-test-input';
    const baseHash = crypto.createHash('sha256').update(baseInput).digest('hex');
    
    // Single bit changes should result in drastically different hashes
    const variations = [
      'avalanche-test-inpuu', // Last character changed
      'avalanche-test-input ', // Space added
      'avalanche-test-inpu', // Character removed
      'Avalanche-test-input', // Case change
    ];

    variations.forEach(variation => {
      const variationHash = crypto.createHash('sha256').update(variation).digest('hex');
      
      // Count different characters between hashes
      let differentChars = 0;
      for (let i = 0; i < 64; i++) {
        if (baseHash[i] !== variationHash[i]) {
          differentChars++;
        }
      }
      
      // Should have many different characters (avalanche effect)
      expect(differentChars).toBeGreaterThan(20); // At least ~30% different
    });
  });

  test('should handle edge cases for hashing', () => {
    const edgeCases = [
      '', // Empty string
      '\0', // Null byte
      ' ', // Single space
      '\n', // Newline
      '\t', // Tab
      'a'.repeat(1000), // Long string
      '🔐🚀🌟', // Unicode
      '\u0000\u0001\u0002', // Control characters
    ];

    edgeCases.forEach(input => {
      const hash = crypto.createHash('sha256').update(input).digest('hex');
      expect(hash).toMatch(/^[a-f0-9]{64}$/);
      expect(hash.length).toBe(64);
    });
  });

  test('should demonstrate collision resistance', () => {
    // Generate many different inputs and verify no collisions
    const inputs = [];
    const hashes = new Set();
    
    // Generate varied inputs
    for (let i = 0; i < 10000; i++) {
      const input = `token-${i}-${Math.random()}-${Date.now()}`;
      inputs.push(input);
      
      const hash = crypto.createHash('sha256').update(input).digest('hex');
      hashes.add(hash);
    }
    
    // All hashes should be unique (no collisions)
    expect(hashes.size).toBe(inputs.length);
  });

  test('should handle concurrent hashing operations', () => {
    const concurrentPromises = Array.from({ length: 1000 }, (_, i) => 
      new Promise(resolve => {
        const input = `concurrent-test-${i}`;
        const hash = crypto.createHash('sha256').update(input).digest('hex');
        resolve({ input, hash });
      })
    );

    return Promise.all(concurrentPromises).then(results => {
      // All should complete successfully
      expect(results.length).toBe(1000);
      
      // All hashes should be unique
      const hashes = results.map(r => r.hash);
      const uniqueHashes = new Set(hashes);
      expect(uniqueHashes.size).toBe(1000);
      
      // All should be valid format
      hashes.forEach(hash => {
        expect(hash).toMatch(/^[a-f0-9]{64}$/);
      });
    });
  });

  test('should handle incremental hashing', () => {
    const fullInput = 'this-is-a-test-input-for-incremental-hashing';
    
    // Hash all at once
    const fullHash = crypto.createHash('sha256').update(fullInput).digest('hex');
    
    // Hash incrementally
    const hasher = crypto.createHash('sha256');
    hasher.update('this-is-a-');
    hasher.update('test-input-');
    hasher.update('for-incremental-');
    hasher.update('hashing');
    const incrementalHash = hasher.digest('hex');
    
    // Should produce the same result
    expect(incrementalHash).toBe(fullHash);
  });

  test('should handle very large inputs', () => {
    // Test with large input (1MB)
    const largeInput = 'x'.repeat(1024 * 1024);
    
    const startTime = process.hrtime.bigint();
    const hash = crypto.createHash('sha256').update(largeInput).digest('hex');
    const endTime = process.hrtime.bigint();
    
    const duration = Number(endTime - startTime) / 1000000; // Convert to milliseconds
    
    expect(hash).toMatch(/^[a-f0-9]{64}$/);
    expect(duration).toBeLessThan(1000); // Should complete within 1 second
  });

  test('should produce deterministic results across platforms', () => {
    // Test vectors for cross-platform consistency
    const testVectors = [
      { input: 'abc', expected: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' },
      { input: '', expected: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
      { input: 'message digest', expected: 'f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650' },
      { input: 'a'.repeat(1000000), expected: 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0' },
    ];

    testVectors.forEach(({ input, expected }) => {
      const hash = crypto.createHash('sha256').update(input).digest('hex');
      expect(hash).toBe(expected);
    });
  });

  test('should handle different encoding types', () => {
    const input = 'test-input-123';
    
    // Different ways to create the same hash
    const hexHash = crypto.createHash('sha256').update(input, 'utf8').digest('hex');
    const base64Hash = crypto.createHash('sha256').update(input, 'utf8').digest('base64');
    const bufferHash = crypto.createHash('sha256').update(Buffer.from(input, 'utf8')).digest('hex');
    
    // Hex and buffer approaches should be identical
    expect(bufferHash).toBe(hexHash);
    
    // Base64 should be different format but same hash
    const base64ToHex = Buffer.from(base64Hash, 'base64').toString('hex');
    expect(base64ToHex).toBe(hexHash);
  });

  test('should maintain hash integrity under stress', () => {
    const stressInputs = [];
    const expectedHashes = [];
    
    // Pre-compute expected hashes
    for (let i = 0; i < 5000; i++) {
      const input = `stress-test-${i}-${Math.random()}`;
      stressInputs.push(input);
      expectedHashes.push(crypto.createHash('sha256').update(input).digest('hex'));
    }
    
    // Hash under stress (all at once)
    const stressHashes = stressInputs.map(input => 
      crypto.createHash('sha256').update(input).digest('hex')
    );
    
    // Should match expected hashes
    expect(stressHashes).toEqual(expectedHashes);
    
    // All should be unique
    const uniqueHashes = new Set(stressHashes);
    expect(uniqueHashes.size).toBe(stressInputs.length);
  });

  test('should handle hash comparison safely', () => {
    const input = 'comparison-test';
    const correctHash = crypto.createHash('sha256').update(input).digest('hex');
    const wrongHash = crypto.createHash('sha256').update('wrong-input').digest('hex');
    
    // Safe comparison (constant time)
    function safeCompare(a: string, b: string): boolean {
      if (a.length !== b.length) return false;
      
      let result = 0;
      for (let i = 0; i < a.length; i++) {
        result |= a.charCodeAt(i) ^ b.charCodeAt(i);
      }
      return result === 0;
    }
    
    expect(safeCompare(correctHash, correctHash)).toBe(true);
    expect(safeCompare(correctHash, wrongHash)).toBe(false);
    
    // Timing should be consistent regardless of match
    const timings = [];
    
    for (let i = 0; i < 100; i++) {
      // Time correct comparison
      const correctStart = process.hrtime.bigint();
      safeCompare(correctHash, correctHash);
      const correctEnd = process.hrtime.bigint();
      
      // Time incorrect comparison
      const wrongStart = process.hrtime.bigint();
      safeCompare(correctHash, wrongHash);
      const wrongEnd = process.hrtime.bigint();
      
      timings.push({
        correct: Number(correctEnd - correctStart),
        wrong: Number(wrongEnd - wrongStart)
      });
    }
    
    const avgCorrect = timings.reduce((sum, t) => sum + t.correct, 0) / timings.length;
    const avgWrong = timings.reduce((sum, t) => sum + t.wrong, 0) / timings.length;
    
    // Timing difference should be minimal (constant time)
    const timingRatio = Math.abs(avgCorrect - avgWrong) / Math.max(avgCorrect, avgWrong);
    expect(timingRatio).toBeLessThan(0.5); // Less than 50% difference
  });
});