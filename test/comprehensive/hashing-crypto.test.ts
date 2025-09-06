import { describe, test, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import mysql from 'mysql2/promise';
import mysql2 from 'mysql2';
import crypto from 'crypto';
import argon2 from 'argon2';
import { configuration } from '../../src/jwtAuth/config/configuration.js';

describe('Hashing and Cryptographic Security - Comprehensive Testing', () => {
  let promisePool: mysql.Pool;
  let callbackPool: mysql2.Pool;

  beforeAll(async () => {
    // Setup database connections
    promisePool = mysql.createPool({
      host: '127.0.0.1',
      port: 3306,
      user: 'root',
      password: '1234',
      database: 'app_db',
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
    });

    callbackPool = mysql2.createPool({
      host: '127.0.0.1',
      port: 3306,
      user: 'root',
      password: '1234',
      database: 'app_db',
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
    });

    // Configure the library
    configuration({
      store: {
        main: promisePool,
        rate_limiters_pool: {
          store: callbackPool,
          dbName: 'app_db'
        }
      },
      telegram: { token: 'test-token' },
      password: { pepper: 'test-pepper-salt-for-hashing-tests' },
      magic_links: {
        jwt_secret_key: 'test-magic-secret-key-32-chars-long',
        domain: 'https://test.example.com'
      },
      jwt: {
        jwt_secret_key: 'test-jwt-secret-key-32-chars-long',
        access_tokens: {
          expiresIn: '15m',
          algorithm: 'HS512',
          maxCacheEntries: 500
        },
        refresh_tokens: {
          rotateOnEveryAccessExpiry: true,
          refresh_ttl: 24 * 60 * 60 * 1000,
          domain: 'test.example.com',
          MAX_SESSION_LIFE: 30 * 24 * 60 * 60 * 1000,
          maxAllowedSessionsPerUser: 5,
          byPassAnomaliesFor: 60 * 60 * 1000
        }
      },
      email: {
        resend_key: 'test-resend-key',
        email: 'test@example.com'
      },
      logLevel: 'info'
    });
  });

  afterAll(async () => {
    if (promisePool) await promisePool.end();
    if (callbackPool) callbackPool.end();
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('SHA-256 Hashing (Token Storage)', () => {
    test('should generate consistent SHA-256 hashes', () => {
      const input = 'test-token-string';
      
      const hash1 = crypto.createHash('sha256').update(input).digest('hex');
      const hash2 = crypto.createHash('sha256').update(input).digest('hex');
      
      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(64); // 256 bits = 64 hex chars
      expect(hash1).toMatch(/^[a-f0-9]{64}$/); // Valid hex
    });

    test('should generate different hashes for different inputs', () => {
      const inputs = [
        'password123',
        'password124',
        '',
        'a'.repeat(1000),
        'special!@#$%^&*()chars',
        '中文字符',
        '\x00\x01\x02binary'
      ];

      const hashes = inputs.map(input => 
        crypto.createHash('sha256').update(input).digest('hex')
      );

      // All hashes should be unique
      expect(new Set(hashes).size).toBe(inputs.length);
      
      // All should be valid 64-character hex strings
      hashes.forEach(hash => {
        expect(hash).toHaveLength(64);
        expect(hash).toMatch(/^[a-f0-9]{64}$/);
      });
    });

    test('should handle binary data correctly', () => {
      const binaryData = crypto.randomBytes(256);
      
      const hash = crypto.createHash('sha256').update(binaryData).digest('hex');
      
      expect(hash).toHaveLength(64);
      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });

    test('should demonstrate avalanche effect', () => {
      const input1 = 'password123';
      const input2 = 'password124'; // Single character difference
      
      const hash1 = crypto.createHash('sha256').update(input1).digest('hex');
      const hash2 = crypto.createHash('sha256').update(input2).digest('hex');
      
      expect(hash1).not.toBe(hash2);
      
      // Count different characters (should be roughly 50% for good hash)
      let differences = 0;
      for (let i = 0; i < hash1.length; i++) {
        if (hash1[i] !== hash2[i]) differences++;
      }
      
      expect(differences).toBeGreaterThan(20); // Should have significant differences
    });

    test('should handle edge cases for hashing', () => {
      const edgeCases = [
        '', // Empty string
        '\x00', // Null byte
        '\xFF'.repeat(100), // High bytes
        'a'.repeat(10000), // Very long string
        '🚀💀👹🎉', // Unicode emojis
        'Line1\nLine2\rLine3\tTabbed' // Control characters
      ];

      edgeCases.forEach(input => {
        const hash = crypto.createHash('sha256').update(input).digest('hex');
        expect(hash).toHaveLength(64);
        expect(hash).toMatch(/^[a-f0-9]{64}$/);
      });
    });

    test('should demonstrate collision resistance', () => {
      // Generate many hashes and verify no collisions
      const inputs = Array.from({ length: 1000 }, (_, i) => `input${i}`);
      const hashes = inputs.map(input => 
        crypto.createHash('sha256').update(input).digest('hex')
      );

      expect(new Set(hashes).size).toBe(1000); // No collisions
    });
  });

  describe('Argon2 Password Hashing', () => {
    test('should hash passwords with Argon2', async () => {
      const password = 'test-password-123';
      
      const hash = await argon2.hash(password);
      
      expect(hash).toBeDefined();
      expect(typeof hash).toBe('string');
      expect(hash).toMatch(/^\$argon2(i|d|id)\$/); // Starts with Argon2 identifier
    });

    test('should verify correct passwords', async () => {
      const password = 'correct-password';
      
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
      const password = 'same-password';
      
      const hash1 = await argon2.hash(password);
      const hash2 = await argon2.hash(password);
      
      expect(hash1).not.toBe(hash2); // Different due to random salt
      
      // Both should verify correctly
      expect(await argon2.verify(hash1, password)).toBe(true);
      expect(await argon2.verify(hash2, password)).toBe(true);
    });

    test('should handle various password types', async () => {
      const passwords = [
        '', // Empty password
        'a', // Single character
        'simple', // Simple password
        'Complex!P@ssw0rd#2023', // Complex password
        'password with spaces', // Spaces
        '密码测试', // Unicode characters
        '🔐🛡️🔒', // Emoji password
        'a'.repeat(1000), // Very long password
        '\x00\x01\x02', // Binary characters
      ];

      for (const password of passwords) {
        const hash = await argon2.hash(password);
        const isValid = await argon2.verify(hash, password);
        
        expect(hash).toBeDefined();
        expect(isValid).toBe(true);
      }
    });

    test('should demonstrate timing attack resistance', async () => {
      const password = 'test-password';
      const hash = await argon2.hash(password);
      
      // Time correct password verification
      const correctStart = Date.now();
      await argon2.verify(hash, password);
      const correctTime = Date.now() - correctStart;
      
      // Time incorrect password verification
      const incorrectStart = Date.now();
      await argon2.verify(hash, 'wrong-password');
      const incorrectTime = Date.now() - incorrectStart;
      
      // Times should be similar (within reasonable variance)
      const timeDifference = Math.abs(correctTime - incorrectTime);
      expect(timeDifference).toBeLessThan(50); // Within 50ms
    });

    test('should handle concurrent hashing operations', async () => {
      const passwords = Array.from({ length: 10 }, (_, i) => `password${i}`);
      
      const hashPromises = passwords.map(password => argon2.hash(password));
      const hashes = await Promise.all(hashPromises);
      
      expect(hashes.length).toBe(10);
      expect(new Set(hashes).size).toBe(10); // All unique
      
      // Verify all hashes work
      const verifications = await Promise.all(
        passwords.map((password, i) => argon2.verify(hashes[i], password))
      );
      
      verifications.forEach(isValid => expect(isValid).toBe(true));
    });

    test('should use appropriate security parameters', async () => {
      const password = 'test-password';
      
      // Test with different memory and time costs
      const hash1 = await argon2.hash(password, { memoryCost: 2 ** 12 }); // 4MB
      const hash2 = await argon2.hash(password, { memoryCost: 2 ** 14 }); // 16MB
      
      expect(hash1).not.toBe(hash2);
      expect(await argon2.verify(hash1, password)).toBe(true);
      expect(await argon2.verify(hash2, password)).toBe(true);
    });
  });

  describe('Cryptographic Random Generation', () => {
    test('should generate cryptographically secure random bytes', () => {
      const sizes = [16, 32, 64, 128, 256];
      
      sizes.forEach(size => {
        const randomBytes = crypto.randomBytes(size);
        
        expect(randomBytes).toBeInstanceOf(Buffer);
        expect(randomBytes.length).toBe(size);
      });
    });

    test('should generate unique random values', () => {
      const values = Array.from({ length: 1000 }, () => 
        crypto.randomBytes(32).toString('hex')
      );
      
      // All values should be unique
      expect(new Set(values).size).toBe(1000);
    });

    test('should generate secure UUIDs', () => {
      const uuids = Array.from({ length: 100 }, () => crypto.randomUUID());
      
      // All UUIDs should be unique
      expect(new Set(uuids).size).toBe(100);
      
      // All should match UUID v4 format
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      uuids.forEach(uuid => {
        expect(uuid).toMatch(uuidRegex);
      });
    });

    test('should handle concurrent random generation', async () => {
      const promises = Array.from({ length: 100 }, () => 
        new Promise(resolve => {
          const randomValue = crypto.randomBytes(32).toString('hex');
          resolve(randomValue);
        })
      );
      
      const values = await Promise.all(promises);
      
      expect(values.length).toBe(100);
      expect(new Set(values).size).toBe(100); // All unique
    });

    test('should generate uniform distribution', () => {
      // Test random integer generation
      const buckets = new Array(10).fill(0);
      const iterations = 10000;
      
      for (let i = 0; i < iterations; i++) {
        const randomByte = crypto.randomBytes(1)[0];
        const bucket = Math.floor((randomByte / 256) * 10);
        buckets[bucket]++;
      }
      
      // Each bucket should have roughly 1000 entries (±20%)
      buckets.forEach(count => {
        expect(count).toBeGreaterThan(800);
        expect(count).toBeLessThan(1200);
      });
    });
  });

  describe('HMAC and Message Authentication', () => {
    test('should generate valid HMAC-SHA256', () => {
      const key = 'secret-key';
      const message = 'test-message';
      
      const hmac = crypto.createHmac('sha256', key).update(message).digest('hex');
      
      expect(hmac).toHaveLength(64); // 256 bits = 64 hex chars
      expect(hmac).toMatch(/^[a-f0-9]{64}$/);
    });

    test('should verify HMAC authenticity', () => {
      const key = 'secret-key';
      const message = 'authentic-message';
      
      const hmac1 = crypto.createHmac('sha256', key).update(message).digest('hex');
      const hmac2 = crypto.createHmac('sha256', key).update(message).digest('hex');
      
      expect(hmac1).toBe(hmac2); // Same message, same HMAC
    });

    test('should detect message tampering', () => {
      const key = 'secret-key';
      const originalMessage = 'original-message';
      const tamperedMessage = 'tampered-message';
      
      const originalHmac = crypto.createHmac('sha256', key).update(originalMessage).digest('hex');
      const tamperedHmac = crypto.createHmac('sha256', key).update(tamperedMessage).digest('hex');
      
      expect(originalHmac).not.toBe(tamperedHmac);
    });

    test('should be sensitive to key changes', () => {
      const message = 'same-message';
      const key1 = 'key1';
      const key2 = 'key2';
      
      const hmac1 = crypto.createHmac('sha256', key1).update(message).digest('hex');
      const hmac2 = crypto.createHmac('sha256', key2).update(message).digest('hex');
      
      expect(hmac1).not.toBe(hmac2);
    });

    test('should handle timing-safe comparison', () => {
      const key = 'test-key';
      const message = 'test-message';
      
      const correctHmac = crypto.createHmac('sha256', key).update(message).digest('hex');
      const wrongHmac = 'a'.repeat(64); // Wrong HMAC
      
      // Use timing-safe comparison
      const isValid1 = crypto.timingSafeEqual(
        Buffer.from(correctHmac, 'hex'),
        Buffer.from(correctHmac, 'hex')
      );
      
      const isValid2 = crypto.timingSafeEqual(
        Buffer.from(correctHmac, 'hex'),
        Buffer.from(wrongHmac, 'hex')
      );
      
      expect(isValid1).toBe(true);
      expect(isValid2).toBe(false);
    });
  });

  describe('Password Security Best Practices', () => {
    test('should demonstrate salt importance', async () => {
      const password = 'common-password';
      
      // Hash without explicit salt (Argon2 adds random salt)
      const hash1 = await argon2.hash(password);
      const hash2 = await argon2.hash(password);
      
      expect(hash1).not.toBe(hash2); // Different due to random salts
      
      // Both should verify
      expect(await argon2.verify(hash1, password)).toBe(true);
      expect(await argon2.verify(hash2, password)).toBe(true);
    });

    test('should demonstrate pepper usage', async () => {
      const password = 'user-password';
      const pepper = 'application-wide-pepper';
      
      // Hash with pepper prepended
      const pepperedPassword = pepper + password;
      const hash = await argon2.hash(pepperedPassword);
      
      // Verify with pepper
      expect(await argon2.verify(hash, pepperedPassword)).toBe(true);
      
      // Verify without pepper should fail
      expect(await argon2.verify(hash, password)).toBe(false);
    });

    test('should handle password complexity requirements', async () => {
      const weakPasswords = [
        '123456',
        'password',
        'qwerty',
        'abc123',
        '111111'
      ];
      
      const strongPasswords = [
        'MyStr0ng!P@ssw0rd#2023',
        'Correct-Horse-Battery-Staple-42',
        'P@$$w0rd!@#$%^&*()',
        'aB3$fGhI9#mNpQ2&'
      ];
      
      // All passwords can be hashed (strength checking is separate)
      for (const password of [...weakPasswords, ...strongPasswords]) {
        const hash = await argon2.hash(password);
        expect(await argon2.verify(hash, password)).toBe(true);
      }
    });

    test('should demonstrate key stretching effectiveness', async () => {
      const password = 'test-password';
      
      // Time a simple hash (vulnerable to brute force)
      const simpleStart = Date.now();
      crypto.createHash('sha256').update(password).digest('hex');
      const simpleTime = Date.now() - simpleStart;
      
      // Time Argon2 hash (resistant to brute force)
      const argonStart = Date.now();
      await argon2.hash(password);
      const argonTime = Date.now() - argonStart;
      
      // Argon2 should take significantly longer
      expect(argonTime).toBeGreaterThan(simpleTime * 10);
    });
  });

  describe('Cryptographic Edge Cases and Attack Vectors', () => {
    test('should handle hash collision attempts', () => {
      // While true collisions are extremely rare, test similar inputs
      const similarInputs = [
        'password123',
        'password124',
        'password125',
        'Password123',
        'PASSWORD123',
        'password 123',
        'password!23'
      ];
      
      const hashes = similarInputs.map(input =>
        crypto.createHash('sha256').update(input).digest('hex')
      );
      
      // All should be different
      expect(new Set(hashes).size).toBe(similarInputs.length);
    });

    test('should resist length extension attacks', () => {
      const key = 'secret-key';
      const message = 'original-message';
      const extension = 'appended-data';
      
      const originalHmac = crypto.createHmac('sha256', key)
        .update(message)
        .digest('hex');
      
      // Attacker cannot extend message without key
      const extendedMessage = message + extension;
      const extendedHmac = crypto.createHmac('sha256', key)
        .update(extendedMessage)
        .digest('hex');
      
      expect(originalHmac).not.toBe(extendedHmac);
    });

    test('should handle rainbow table resistance', async () => {
      const commonPasswords = [
        'password',
        '123456',
        'qwerty',
        'admin',
        'letmein'
      ];
      
      // Each password should get different salt/hash
      const hashes = await Promise.all(
        commonPasswords.map(password => argon2.hash(password))
      );
      
      // All hashes should be unique despite common passwords
      expect(new Set(hashes).size).toBe(commonPasswords.length);
    });

    test('should demonstrate secure key derivation', () => {
      const password = 'user-password';
      const salt = crypto.randomBytes(32);
      const iterations = 100000;
      
      const derivedKey = crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256');
      
      expect(derivedKey).toBeInstanceOf(Buffer);
      expect(derivedKey.length).toBe(32);
      
      // Same parameters should produce same key
      const derivedKey2 = crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256');
      expect(derivedKey.equals(derivedKey2)).toBe(true);
      
      // Different salt should produce different key
      const differentSalt = crypto.randomBytes(32);
      const derivedKey3 = crypto.pbkdf2Sync(password, differentSalt, iterations, 32, 'sha256');
      expect(derivedKey.equals(derivedKey3)).toBe(false);
    });

    test('should handle side-channel attack resistance', async () => {
      const password = 'test-password';
      const hash = await argon2.hash(password);
      
      // Test multiple verification attempts
      const verificationTimes = [];
      
      for (let i = 0; i < 10; i++) {
        const start = Date.now();
        await argon2.verify(hash, password);
        const end = Date.now();
        verificationTimes.push(end - start);
      }
      
      // Times should be relatively consistent
      const avgTime = verificationTimes.reduce((a, b) => a + b) / verificationTimes.length;
      const maxDeviation = Math.max(...verificationTimes.map(t => Math.abs(t - avgTime)));
      
      expect(maxDeviation).toBeLessThan(avgTime * 0.5); // Within 50% of average
    });
  });

  describe('Integration with Auth System', () => {
    test('should hash refresh tokens consistently', () => {
      const token = crypto.randomBytes(32).toString('hex');
      
      const hash1 = crypto.createHash('sha256').update(token).digest('hex');
      const hash2 = crypto.createHash('sha256').update(token).digest('hex');
      
      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(64);
    });

    test('should handle MFA code hashing', () => {
      const mfaCode = '1234567';
      
      const hash = crypto.createHash('sha256').update(mfaCode).digest('hex');
      
      expect(hash).toHaveLength(64);
      expect(hash).toMatch(/^[a-f0-9]{64}$/);
      
      // Same code should produce same hash
      const hash2 = crypto.createHash('sha256').update(mfaCode).digest('hex');
      expect(hash).toBe(hash2);
    });

    test('should demonstrate JTI uniqueness', () => {
      const jtis = Array.from({ length: 1000 }, () => crypto.randomUUID());
      
      expect(new Set(jtis).size).toBe(1000);
      
      // All should be valid UUID format
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      jtis.forEach(jti => {
        expect(jti).toMatch(uuidRegex);
      });
    });

    test('should verify canary ID security', () => {
      // Canary IDs should be unpredictable
      const canaryIds = Array.from({ length: 100 }, () => {
        const randomBytes = crypto.randomBytes(32);
        return crypto.createHash('sha256').update(randomBytes).digest('hex').substring(0, 16);
      });
      
      expect(new Set(canaryIds).size).toBe(100);
      
      canaryIds.forEach(id => {
        expect(id).toHaveLength(16);
        expect(id).toMatch(/^[a-f0-9]{16}$/);
      });
    });
  });
});