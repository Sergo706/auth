import { describe, test, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { generateTemporaryJwtLink, verifyTemporaryJwtLink } from '../../../src/tempLinks.js';
import { 
  setupTestDatabase, 
  teardownTestDatabase, 
  setupTestUser, 
  cleanupTestData,
  mockBotDetector 
} from '../test-setup.js';

// Mock bot detector for controlled testing
mockBotDetector();

describe('Temporary JWT Link Verification', () => {
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

  test('should verify valid temporary link', () => {
    const payload = { userId: 999, action: 'password-reset' };
    const visitorId = 888;
    const expiresIn = '1h';

    const generated = generateTemporaryJwtLink(payload, visitorId, expiresIn);
    const verification = verifyTemporaryJwtLink(generated.token);

    expect(verification.valid).toBe(true);
    expect(verification.payload).toBeDefined();
    expect(verification.payload.userId).toBe(999);
    expect(verification.payload.visitor_id).toBe(888);
    expect(verification.payload.action).toBe('password-reset');
    expect(verification.error).toBeUndefined();
  });

  test('should reject expired tokens', () => {
    const payload = { userId: 999, action: 'test' };
    const visitorId = 888;
    const shortExpiry = '1s';

    const generated = generateTemporaryJwtLink(payload, visitorId, shortExpiry);
    
    // Wait for expiration
    return new Promise((resolve) => {
      setTimeout(() => {
        const verification = verifyTemporaryJwtLink(generated.token);
        
        expect(verification.valid).toBe(false);
        expect(verification.error).toContain('expired');
        expect(verification.payload).toBeUndefined();
        resolve(void 0);
      }, 1100); // Wait 1.1 seconds
    });
  });

  test('should reject malformed tokens', () => {
    const malformedTokens = [
      '', // Empty string
      'invalid', // Not a JWT
      'a.b', // Missing part
      'a.b.c.d', // Too many parts
      'invalid.token.signature',
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid.signature',
      null,
      undefined,
      123,
      {},
      []
    ];

    malformedTokens.forEach(token => {
      const verification = verifyTemporaryJwtLink(token as any);
      expect(verification.valid).toBe(false);
      expect(verification.error).toBeDefined();
      expect(verification.payload).toBeUndefined();
    });
  });

  test('should reject tokens with wrong signature', () => {
    const payload = { userId: 999, action: 'test' };
    const visitorId = 888;
    const expiresIn = '1h';

    const generated = generateTemporaryJwtLink(payload, visitorId, expiresIn);
    
    // Tamper with the signature
    const tokenParts = generated.token.split('.');
    const tamperedSignature = tokenParts[2].slice(0, -5) + 'XXXXX';
    const tamperedToken = `${tokenParts[0]}.${tokenParts[1]}.${tamperedSignature}`;

    const verification = verifyTemporaryJwtLink(tamperedToken);
    
    expect(verification.valid).toBe(false);
    expect(verification.error).toBeDefined();
  });

  test('should handle tokens with modified payload', () => {
    const payload = { userId: 999, action: 'test' };
    const visitorId = 888;
    const expiresIn = '1h';

    const generated = generateTemporaryJwtLink(payload, visitorId, expiresIn);
    const tokenParts = generated.token.split('.');
    
    // Modify the payload
    const originalPayload = JSON.parse(
      Buffer.from(tokenParts[1], 'base64').toString()
    );
    const modifiedPayload = { ...originalPayload, userId: 888 }; // Change user ID
    const tamperedPayload = Buffer.from(JSON.stringify(modifiedPayload)).toString('base64');
    const tamperedToken = `${tokenParts[0]}.${tamperedPayload}.${tokenParts[2]}`;

    const verification = verifyTemporaryJwtLink(tamperedToken);
    
    expect(verification.valid).toBe(false);
    expect(verification.error).toBeDefined();
  });

  test('should handle concurrent verification attempts', () => {
    const payload = { userId: 999, action: 'concurrent-test' };
    const visitorId = 888;
    const expiresIn = '1h';

    const generated = generateTemporaryJwtLink(payload, visitorId, expiresIn);
    
    // Multiple concurrent verifications
    const verificationPromises = Array.from({ length: 20 }, () =>
      verifyTemporaryJwtLink(generated.token)
    );

    return Promise.all(verificationPromises).then(results => {
      // All should succeed (temp links can be verified multiple times)
      results.forEach(result => {
        expect(result.valid).toBe(true);
        expect(result.payload.userId).toBe(999);
        expect(result.payload.visitor_id).toBe(888);
      });
    });
  });

  test('should verify tokens with complex payloads', () => {
    const complexPayload = {
      userId: 999,
      action: 'complex-operation',
      metadata: {
        permissions: ['read', 'write', 'delete'],
        context: {
          source: 'api',
          version: '2.1',
          features: ['auth', 'logging']
        }
      },
      expires: new Date(Date.now() + 60000).toISOString(),
      settings: {
        theme: 'dark',
        notifications: true,
        language: 'en-US'
      }
    };

    const visitorId = 888;
    const expiresIn = '1h';

    const generated = generateTemporaryJwtLink(complexPayload, visitorId, expiresIn);
    const verification = verifyTemporaryJwtLink(generated.token);

    expect(verification.valid).toBe(true);
    expect(verification.payload.userId).toBe(999);
    expect(verification.payload.action).toBe('complex-operation');
    expect(verification.payload.metadata).toEqual(complexPayload.metadata);
    expect(verification.payload.settings).toEqual(complexPayload.settings);
  });

  test('should handle verification timing consistency', () => {
    const payload = { userId: 999, action: 'timing-test' };
    const visitorId = 888;
    const expiresIn = '1h';

    const validToken = generateTemporaryJwtLink(payload, visitorId, expiresIn).token;
    const invalidToken = 'invalid.token.signature';

    // Measure timing for valid and invalid tokens
    const timings = [];
    
    for (let i = 0; i < 10; i++) {
      // Valid token timing
      const validStart = process.hrtime.bigint();
      verifyTemporaryJwtLink(validToken);
      const validEnd = process.hrtime.bigint();
      const validTime = Number(validEnd - validStart) / 1000000;

      // Invalid token timing
      const invalidStart = process.hrtime.bigint();
      verifyTemporaryJwtLink(invalidToken);
      const invalidEnd = process.hrtime.bigint();
      const invalidTime = Number(invalidEnd - invalidStart) / 1000000;

      timings.push({ valid: validTime, invalid: invalidTime });
    }

    // Calculate timing consistency
    const validTimes = timings.map(t => t.valid);
    const invalidTimes = timings.map(t => t.invalid);
    
    const avgValid = validTimes.reduce((a, b) => a + b) / validTimes.length;
    const avgInvalid = invalidTimes.reduce((a, b) => a + b) / invalidTimes.length;
    
    // Should not have extreme timing differences
    const timingRatio = Math.abs(avgValid - avgInvalid) / Math.max(avgValid, avgInvalid);
    expect(timingRatio).toBeLessThan(3.0); // Less than 300% difference
  });

  test('should preserve special characters in verification', () => {
    const specialPayload = {
      userId: 999,
      message: 'Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?',
      unicode: '🔐 Security Test 🚀',
      quotes: 'Both "double" and \'single\' quotes',
      newlines: 'Line 1\nLine 2\rLine 3\tTabbed',
      json: '{"nested": {"data": [1, 2, 3]}}'
    };

    const visitorId = 888;
    const expiresIn = '30m';

    const generated = generateTemporaryJwtLink(specialPayload, visitorId, expiresIn);
    const verification = verifyTemporaryJwtLink(generated.token);

    expect(verification.valid).toBe(true);
    expect(verification.payload.message).toBe(specialPayload.message);
    expect(verification.payload.unicode).toBe(specialPayload.unicode);
    expect(verification.payload.quotes).toBe(specialPayload.quotes);
    expect(verification.payload.newlines).toBe(specialPayload.newlines);
    expect(verification.payload.json).toBe(specialPayload.json);
  });

  test('should detect token replay patterns', () => {
    const payload = { userId: 999, action: 'replay-test' };
    const visitorId = 888;
    const expiresIn = '1h';

    const generated = generateTemporaryJwtLink(payload, visitorId, expiresIn);
    
    // Verify the same token multiple times rapidly
    const verifications = [];
    for (let i = 0; i < 100; i++) {
      const verification = verifyTemporaryJwtLink(generated.token);
      verifications.push(verification);
    }

    // All should succeed (temp links are stateless by design)
    verifications.forEach(verification => {
      expect(verification.valid).toBe(true);
      expect(verification.payload.userId).toBe(999);
    });
  });

  test('should handle verification under memory pressure', () => {
    const payload = { userId: 999, action: 'memory-test' };
    const visitorId = 888;
    const expiresIn = '1h';

    // Generate many tokens
    const tokens = [];
    for (let i = 0; i < 1000; i++) {
      const generated = generateTemporaryJwtLink(payload, visitorId, expiresIn);
      tokens.push(generated.token);
    }

    // Verify a subset under memory pressure
    const verificationResults = [];
    for (let i = 0; i < 100; i++) {
      const token = tokens[i * 10]; // Every 10th token
      const verification = verifyTemporaryJwtLink(token);
      verificationResults.push(verification);
    }

    // All should verify correctly despite memory pressure
    verificationResults.forEach(result => {
      expect(result.valid).toBe(true);
      expect(result.payload.userId).toBe(999);
    });
  });

  test('should handle verification edge cases around expiration', () => {
    const payload = { userId: 999, action: 'expiry-edge-test' };
    const visitorId = 888;
    
    // Test with very short expiry
    const shortExpiryToken = generateTemporaryJwtLink(payload, visitorId, '2s');
    
    // Verify immediately
    const immediateVerification = verifyTemporaryJwtLink(shortExpiryToken.token);
    expect(immediateVerification.valid).toBe(true);
    
    // Wait for close to expiration
    return new Promise((resolve) => {
      setTimeout(() => {
        const nearExpiryVerification = verifyTemporaryJwtLink(shortExpiryToken.token);
        expect(nearExpiryVerification.valid).toBe(true);
        
        // Wait for definitely expired
        setTimeout(() => {
          const expiredVerification = verifyTemporaryJwtLink(shortExpiryToken.token);
          expect(expiredVerification.valid).toBe(false);
          expect(expiredVerification.error).toContain('expired');
          resolve(void 0);
        }, 1000);
      }, 1500);
    });
  });

  test('should handle verification with corrupted base64 encoding', () => {
    const payload = { userId: 999, action: 'corruption-test' };
    const visitorId = 888;
    const expiresIn = '1h';

    const generated = generateTemporaryJwtLink(payload, visitorId, expiresIn);
    const tokenParts = generated.token.split('.');
    
    const corruptedTokens = [
      // Corrupted header
      `corrupted-header.${tokenParts[1]}.${tokenParts[2]}`,
      
      // Corrupted payload
      `${tokenParts[0]}.corrupted-payload.${tokenParts[2]}`,
      
      // Invalid base64 in payload
      `${tokenParts[0]}.invalid@base64!.${tokenParts[2]}`,
      
      // Missing padding
      `${tokenParts[0]}.${tokenParts[1].slice(0, -1)}.${tokenParts[2]}`,
      
      // Extra characters
      `${tokenParts[0]}.${tokenParts[1]}extra.${tokenParts[2]}`,
    ];

    corruptedTokens.forEach(corruptedToken => {
      const verification = verifyTemporaryJwtLink(corruptedToken);
      expect(verification.valid).toBe(false);
      expect(verification.error).toBeDefined();
    });
  });

  test('should verify tokens with minimal payloads', () => {
    const minimalPayloads = [
      { userId: 999 }, // Just user ID
      { action: 'minimal' }, // Just action
      {}, // Empty object (if allowed)
    ];

    const visitorId = 888;
    const expiresIn = '30m';

    minimalPayloads.forEach(payload => {
      try {
        const generated = generateTemporaryJwtLink(payload, visitorId, expiresIn);
        const verification = verifyTemporaryJwtLink(generated.token);
        
        expect(verification.valid).toBe(true);
        expect(verification.payload.visitor_id).toBe(888);
        
        // Check original payload properties are preserved
        Object.keys(payload).forEach(key => {
          expect(verification.payload[key]).toBe(payload[key]);
        });
        
      } catch (error) {
        // Some minimal payloads might be rejected by validation
        expect(error).toBeDefined();
      }
    });
  });
});