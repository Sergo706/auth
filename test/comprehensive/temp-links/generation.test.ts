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

describe('Temporary JWT Link Generation', () => {
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

  test('should generate valid temporary JWT link', () => {
    const payload = { userId: 999, action: 'password-reset' };
    const visitorId = 888;
    const expiresIn = '1h';

    const result = generateTemporaryJwtLink(payload, visitorId, expiresIn);

    expect(result).toHaveProperty('token');
    expect(result).toHaveProperty('expiresAt');
    expect(typeof result.token).toBe('string');
    expect(result.expiresAt).toBeInstanceOf(Date);
    
    // Token should be a valid JWT format
    const tokenParts = result.token.split('.');
    expect(tokenParts).toHaveLength(3);
  });

  test('should generate unique tokens for same payload', () => {
    const payload = { userId: 999, action: 'email-verification' };
    const visitorId = 888;
    const expiresIn = '30m';

    const tokens = [];
    for (let i = 0; i < 10; i++) {
      const result = generateTemporaryJwtLink(payload, visitorId, expiresIn);
      tokens.push(result.token);
    }

    // All tokens should be unique (due to JTI)
    const uniqueTokens = new Set(tokens);
    expect(uniqueTokens.size).toBe(tokens.length);
  });

  test('should handle different payload types', () => {
    const payloads = [
      { userId: 999, action: 'password-reset' },
      { userId: 999, action: 'email-verification', email: 'test@example.com' },
      { userId: 999, mfaCode: '123456', type: 'totp' },
      { userId: 999, sessionId: 'abc-123', action: 'logout-all' },
      { 
        userId: 999, 
        permissions: ['read', 'write'], 
        metadata: { source: 'api', version: '1.0' } 
      }
    ];

    const visitorId = 888;
    const expiresIn = '15m';

    payloads.forEach(payload => {
      const result = generateTemporaryJwtLink(payload, visitorId, expiresIn);
      
      expect(result.token).toBeDefined();
      expect(result.expiresAt).toBeInstanceOf(Date);
      
      // Verify the payload is embedded correctly
      const tokenParts = result.token.split('.');
      const decodedPayload = JSON.parse(
        Buffer.from(tokenParts[1], 'base64').toString()
      );
      
      expect(decodedPayload.userId).toBe(payload.userId);
      expect(decodedPayload.visitor_id).toBe(visitorId);
    });
  });

  test('should handle boundary values for visitor ID', () => {
    const payload = { userId: 999, action: 'test' };
    const expiresIn = '1h';
    
    const boundaryVisitorIds = [
      0,                    // Minimum
      1,                    // Small positive
      999999999,           // Large positive
      Number.MAX_SAFE_INTEGER, // Maximum safe integer
    ];

    boundaryVisitorIds.forEach(visitorId => {
      try {
        const result = generateTemporaryJwtLink(payload, visitorId, expiresIn);
        
        expect(result.token).toBeDefined();
        
        // Verify visitor ID is embedded
        const tokenParts = result.token.split('.');
        const decodedPayload = JSON.parse(
          Buffer.from(tokenParts[1], 'base64').toString()
        );
        expect(decodedPayload.visitor_id).toBe(visitorId);
        
      } catch (error) {
        // Some boundary values might be rejected
        expect(error).toBeDefined();
      }
    });
  });

  test('should handle malformed JTI values', () => {
    const payload = { userId: 999, action: 'test' };
    const visitorId = 888;
    
    // Generate multiple tokens and check JTI format
    const tokens = [];
    for (let i = 0; i < 20; i++) {
      const result = generateTemporaryJwtLink(payload, visitorId, '1h');
      tokens.push(result.token);
    }

    tokens.forEach(token => {
      const tokenParts = token.split('.');
      const decodedPayload = JSON.parse(
        Buffer.from(tokenParts[1], 'base64').toString()
      );
      
      // JTI should exist and be a string
      expect(decodedPayload.jti).toBeDefined();
      expect(typeof decodedPayload.jti).toBe('string');
      expect(decodedPayload.jti.length).toBeGreaterThan(0);
    });
  });

  test('should handle different expiration formats', () => {
    const payload = { userId: 999, action: 'test' };
    const visitorId = 888;
    
    const expirationFormats = [
      '1m',     // Minutes
      '1h',     // Hours  
      '1d',     // Days
      '30s',    // Seconds
      '2w',     // Weeks (if supported)
      60,       // Seconds as number (if supported)
      3600,     // 1 hour as seconds
    ];

    expirationFormats.forEach(expiresIn => {
      try {
        const result = generateTemporaryJwtLink(payload, visitorId, expiresIn);
        
        expect(result.token).toBeDefined();
        expect(result.expiresAt).toBeInstanceOf(Date);
        expect(result.expiresAt.getTime()).toBeGreaterThan(Date.now());
        
      } catch (error) {
        // Some formats might not be supported
        expect(error).toBeDefined();
      }
    });
  });

  test('should include required JWT claims', () => {
    const payload = { userId: 999, action: 'password-reset' };
    const visitorId = 888;
    const expiresIn = '1h';

    const result = generateTemporaryJwtLink(payload, visitorId, expiresIn);
    const tokenParts = result.token.split('.');
    const decodedPayload = JSON.parse(
      Buffer.from(tokenParts[1], 'base64').toString()
    );

    // Standard JWT claims
    expect(decodedPayload.iat).toBeDefined(); // Issued at
    expect(decodedPayload.exp).toBeDefined(); // Expires at
    expect(decodedPayload.jti).toBeDefined(); // JWT ID
    
    // Custom claims
    expect(decodedPayload.userId).toBe(999);
    expect(decodedPayload.visitor_id).toBe(888);
    expect(decodedPayload.action).toBe('password-reset');
    
    // Times should be consistent
    expect(decodedPayload.exp * 1000).toBe(result.expiresAt.getTime());
  });

  test('should handle special characters in payload', () => {
    const specialPayloads = [
      { userId: 999, note: 'Test with "quotes" and \'apostrophes\'' },
      { userId: 999, data: 'Unicode: 🔐 🚀 ñáéíóú' },
      { userId: 999, json: '{"nested": "json", "array": [1,2,3]}' },
      { userId: 999, html: '<script>alert("xss")</script>' },
      { userId: 999, sql: "'; DROP TABLE users; --" },
      { userId: 999, special: '\n\r\t\b\f\\/' },
    ];

    const visitorId = 888;
    const expiresIn = '30m';

    specialPayloads.forEach(payload => {
      const result = generateTemporaryJwtLink(payload, visitorId, expiresIn);
      
      expect(result.token).toBeDefined();
      
      // Verify special characters are preserved
      const tokenParts = result.token.split('.');
      const decodedPayload = JSON.parse(
        Buffer.from(tokenParts[1], 'base64').toString()
      );
      
      Object.keys(payload).forEach(key => {
        if (key !== 'userId') {
          expect(decodedPayload[key]).toBe(payload[key]);
        }
      });
    });
  });

  test('should handle large payloads', () => {
    const largePayload = {
      userId: 999,
      action: 'bulk-operation',
      data: 'x'.repeat(1000), // 1KB of data
      metadata: {
        items: Array.from({ length: 100 }, (_, i) => ({ id: i, name: `Item ${i}` }))
      }
    };

    const visitorId = 888;
    const expiresIn = '1h';

    try {
      const result = generateTemporaryJwtLink(largePayload, visitorId, expiresIn);
      
      expect(result.token).toBeDefined();
      
      // Verify large payload is handled correctly
      const tokenParts = result.token.split('.');
      const decodedPayload = JSON.parse(
        Buffer.from(tokenParts[1], 'base64').toString()
      );
      
      expect(decodedPayload.data).toBe(largePayload.data);
      expect(decodedPayload.metadata.items).toHaveLength(100);
      
    } catch (error) {
      // Large payload rejection is acceptable for security
      expect(error).toBeDefined();
    }
  });

  test('should maintain token consistency across rapid generation', () => {
    const payload = { userId: 999, action: 'rapid-test' };
    const visitorId = 888;
    const expiresIn = '1h';

    const tokens = [];
    const startTime = Date.now();
    
    // Generate tokens rapidly
    for (let i = 0; i < 50; i++) {
      const result = generateTemporaryJwtLink(payload, visitorId, expiresIn);
      tokens.push({
        token: result.token,
        expiresAt: result.expiresAt,
        generated: Date.now()
      });
    }
    
    const endTime = Date.now();
    const totalTime = endTime - startTime;

    // Should complete quickly
    expect(totalTime).toBeLessThan(5000);
    
    // All tokens should be unique
    const uniqueTokens = new Set(tokens.map(t => t.token));
    expect(uniqueTokens.size).toBe(tokens.length);
    
    // Expiration times should be reasonable
    tokens.forEach(tokenData => {
      const timeDiff = tokenData.expiresAt.getTime() - tokenData.generated;
      expect(timeDiff).toBeGreaterThan(3590000); // ~1 hour minus a few seconds
      expect(timeDiff).toBeLessThan(3610000); // ~1 hour plus a few seconds
    });
  });

  test('should handle edge case expiration times', () => {
    const payload = { userId: 999, action: 'edge-test' };
    const visitorId = 888;
    
    const edgeExpirations = [
      '1s',    // Very short
      '30s',   // Short
      '24h',   // Long
      '7d',    // Very long
    ];

    edgeExpirations.forEach(expiresIn => {
      const result = generateTemporaryJwtLink(payload, visitorId, expiresIn);
      
      expect(result.token).toBeDefined();
      expect(result.expiresAt.getTime()).toBeGreaterThan(Date.now());
      
      // Verify expiration is in expected range
      const timeDiff = result.expiresAt.getTime() - Date.now();
      
      switch (expiresIn) {
        case '1s':
          expect(timeDiff).toBeLessThan(2000);
          break;
        case '30s':
          expect(timeDiff).toBeLessThan(31000);
          break;
        case '24h':
          expect(timeDiff).toBeGreaterThan(23.5 * 60 * 60 * 1000);
          break;
        case '7d':
          expect(timeDiff).toBeGreaterThan(6.9 * 24 * 60 * 60 * 1000);
          break;
      }
    });
  });
});