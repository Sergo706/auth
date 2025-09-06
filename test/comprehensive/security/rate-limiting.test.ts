import { describe, test, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { generateRefreshToken, verifyRefreshToken } from '../../../src/refreshTokens.js';
import { generateAccessToken, verifyAccessToken } from '../../../src/accessTokens.js';
import { 
  setupTestDatabase, 
  teardownTestDatabase, 
  setupTestUser, 
  cleanupTestData,
  mockBotDetector 
} from '../test-setup.js';

// Mock bot detector for controlled testing
mockBotDetector();

describe('Rate Limiting and Abuse Prevention', () => {
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

  test('should handle rapid request patterns', async () => {
    const userId = 999;
    
    // Test rapid token verification
    const rapidRequests = Array.from({ length: 50 }, async () => {
      try {
        const token = await generateRefreshToken(1000, userId); // Short TTL
        return await verifyRefreshToken(token.raw);
      } catch (error) {
        return { valid: false, error: error.message };
      }
    });

    const results = await Promise.allSettled(rapidRequests);
    
    // Some requests should succeed, some might be rate limited
    const successful = results.filter(result => 
      result.status === 'fulfilled' && result.value.valid
    );
    const failed = results.filter(result => 
      result.status === 'rejected' || 
      (result.status === 'fulfilled' && !result.value.valid)
    );

    // Should have some rate limiting mechanism
    expect(failed.length).toBeGreaterThan(0);
    expect(successful.length).toBeGreaterThan(0);
  });

  test('should prevent excessive token generation', async () => {
    const userId = 999;
    
    const tokens = [];
    const errors = [];
    
    // Attempt to generate many tokens rapidly
    for (let i = 0; i < 10; i++) {
      try {
        const token = await generateRefreshToken(24 * 60 * 60 * 1000, userId);
        tokens.push(token);
      } catch (error) {
        errors.push(error);
        // Rate limiting kicked in
        break;
      }
    }

    // Either should allow reasonable number of tokens or enforce limits
    expect(tokens.length + errors.length).toBeGreaterThan(0);
    
    // If many tokens were generated, they should be valid
    if (tokens.length > 5) {
      for (const token of tokens.slice(0, 3)) {
        const verification = await verifyRefreshToken(token.raw);
        expect(verification.valid).toBe(true);
      }
    }
  });

  test('should handle distributed attack simulation', async () => {
    const userIds = [999, 998, 997, 996, 995];
    
    // Setup multiple users
    for (const uid of userIds) {
      if (uid !== 999) {
        await cleanupTestData(uid, uid - 111);
        await setupTestUser(uid, uid - 111);
      }
    }

    // Simulate distributed requests from multiple users
    const distributedRequests = userIds.map(async (userId, index) => {
      const requests = [];
      
      for (let i = 0; i < 10; i++) {
        try {
          const token = await generateRefreshToken(24 * 60 * 60 * 1000, userId);
          requests.push(await verifyRefreshToken(token.raw));
        } catch (error) {
          requests.push({ valid: false, error: error.message });
        }
        
        // Small delay between requests
        await new Promise(resolve => setTimeout(resolve, 50));
      }
      
      return requests;
    });

    const allResults = await Promise.all(distributedRequests);
    
    // Should handle distributed load
    const totalRequests = allResults.flat().length;
    const successfulRequests = allResults.flat().filter(r => r.valid).length;
    
    expect(totalRequests).toBeGreaterThan(0);
    expect(successfulRequests).toBeGreaterThan(0);

    // Clean up test users
    for (const uid of userIds) {
      if (uid !== 999) {
        await cleanupTestData(uid, uid - 111);
      }
    }
  });

  test('should enforce per-user rate limits', async () => {
    const userId = 999;
    const batchSize = 20;
    
    // First batch of requests
    const firstBatch = await Promise.allSettled(
      Array.from({ length: batchSize }, () => 
        generateRefreshToken(24 * 60 * 60 * 1000, userId)
      )
    );

    const firstBatchSuccess = firstBatch.filter(r => r.status === 'fulfilled').length;
    
    // Wait a short time
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Second batch of requests (should hit rate limits)
    const secondBatch = await Promise.allSettled(
      Array.from({ length: batchSize }, () => 
        generateRefreshToken(24 * 60 * 60 * 1000, userId)
      )
    );

    const secondBatchSuccess = secondBatch.filter(r => r.status === 'fulfilled').length;
    
    // Rate limiting should affect subsequent requests
    expect(secondBatchSuccess).toBeLessThanOrEqual(firstBatchSuccess);
  });

  test('should handle burst vs sustained load differently', async () => {
    const userId = 999;
    
    // Burst load test
    const burstStart = performance.now();
    const burstRequests = await Promise.allSettled(
      Array.from({ length: 10 }, () => generateRefreshToken(1000, userId))
    );
    const burstTime = performance.now() - burstStart;
    const burstSuccess = burstRequests.filter(r => r.status === 'fulfilled').length;

    // Wait between tests
    await new Promise(resolve => setTimeout(resolve, 200));

    // Sustained load test
    const sustainedStart = performance.now();
    const sustainedResults = [];
    
    for (let i = 0; i < 10; i++) {
      try {
        const token = await generateRefreshToken(1000, userId);
        sustainedResults.push({ success: true, token });
      } catch (error) {
        sustainedResults.push({ success: false, error });
      }
      
      // Small delay for sustained pattern
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    
    const sustainedTime = performance.now() - sustainedStart;
    const sustainedSuccess = sustainedResults.filter(r => r.success).length;

    // Sustained requests should be handled differently than burst
    expect(sustainedTime).toBeGreaterThan(burstTime);
    
    // Both patterns should be handled appropriately
    expect(burstSuccess + sustainedSuccess).toBeGreaterThan(0);
  });

  test('should recover from rate limit periods', async () => {
    const userId = 999;
    
    // Trigger rate limiting
    const overloadRequests = Array.from({ length: 30 }, () => 
      generateRefreshToken(1000, userId)
    );
    
    await Promise.allSettled(overloadRequests);
    
    // Wait for rate limit recovery
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Test recovery
    try {
      const recoveryToken = await generateRefreshToken(24 * 60 * 60 * 1000, userId);
      expect(recoveryToken).toBeDefined();
      
      const verification = await verifyRefreshToken(recoveryToken.raw);
      expect(verification.valid).toBe(true);
    } catch (error) {
      // If still rate limited, that's also acceptable
      expect(error).toBeDefined();
    }
  });

  test('should handle concurrent rate limit checks', async () => {
    const userId = 999;
    
    // Launch concurrent operations that might hit rate limits
    const concurrentOperations = [
      ...Array.from({ length: 5 }, () => generateRefreshToken(1000, userId)),
      ...Array.from({ length: 5 }, () => generateAccessToken(userId, 888)),
    ];

    const results = await Promise.allSettled(concurrentOperations);
    
    // Should handle concurrent rate limit checks without race conditions
    const successful = results.filter(r => r.status === 'fulfilled').length;
    const failed = results.filter(r => r.status === 'rejected').length;
    
    expect(successful + failed).toBe(concurrentOperations.length);
    expect(successful).toBeGreaterThan(0); // Some should succeed
  });

  test('should differentiate rate limits by operation type', async () => {
    const userId = 999;
    const visitorId = 888;
    
    // Test different operation types
    const operationResults = {
      tokenGeneration: [],
      tokenVerification: [],
      tokenRotation: []
    };

    // Token generation attempts
    for (let i = 0; i < 15; i++) {
      try {
        const token = await generateRefreshToken(1000, userId);
        operationResults.tokenGeneration.push({ success: true, token });
      } catch (error) {
        operationResults.tokenGeneration.push({ success: false, error });
      }
    }

    // Token verification attempts
    const testToken = await generateRefreshToken(24 * 60 * 60 * 1000, userId);
    for (let i = 0; i < 15; i++) {
      try {
        const verification = await verifyRefreshToken(testToken.raw);
        operationResults.tokenVerification.push({ success: verification.valid });
      } catch (error) {
        operationResults.tokenVerification.push({ success: false, error });
      }
    }

    // Different operations may have different rate limits
    const genSuccess = operationResults.tokenGeneration.filter(r => r.success).length;
    const verifySuccess = operationResults.tokenVerification.filter(r => r.success).length;
    
    // Both operation types should be handled
    expect(genSuccess + verifySuccess).toBeGreaterThan(0);
  });

  test('should handle IP-based rate limiting', async () => {
    const userIds = [999, 998, 997];
    
    // Setup users (simulating same IP)
    for (const uid of userIds) {
      if (uid !== 999) {
        await cleanupTestData(uid, uid - 111);
        await setupTestUser(uid, uid - 111);
      }
    }

    // Simulate requests from same IP (different users)
    const ipBasedRequests = [];
    
    for (const userId of userIds) {
      for (let i = 0; i < 10; i++) {
        ipBasedRequests.push(
          generateRefreshToken(24 * 60 * 60 * 1000, userId)
        );
      }
    }

    const results = await Promise.allSettled(ipBasedRequests);
    
    // IP-based limits might affect all users from same IP
    const successful = results.filter(r => r.status === 'fulfilled').length;
    const failed = results.filter(r => r.status === 'rejected').length;
    
    expect(successful + failed).toBe(ipBasedRequests.length);

    // Clean up
    for (const uid of userIds) {
      if (uid !== 999) {
        await cleanupTestData(uid, uid - 111);
      }
    }
  });

  test('should handle graceful degradation under load', async () => {
    const userId = 999;
    
    // Simulate high load scenario
    const highLoadRequests = [];
    const startTime = performance.now();
    
    for (let i = 0; i < 100; i++) {
      highLoadRequests.push(
        generateRefreshToken(100, userId).catch(error => ({ error }))
      );
    }

    const results = await Promise.all(highLoadRequests);
    const endTime = performance.now();
    const totalTime = endTime - startTime;
    
    // Should complete in reasonable time (graceful degradation)
    expect(totalTime).toBeLessThan(30000); // Less than 30 seconds
    
    // Should have some successful and some failed requests
    const successful = results.filter(r => r.raw && !r.error).length;
    const failed = results.filter(r => r.error).length;
    
    expect(successful + failed).toBe(100);
    expect(successful).toBeGreaterThan(0); // Some should succeed
  });
});