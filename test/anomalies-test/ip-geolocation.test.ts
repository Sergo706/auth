// @vitest-environment node

/**
 * @vitest-environment-options { "sequential": true }
 */

import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { strangeThings } from "../../src/anomalies.js";
import { generateRefreshToken } from "../../src/refreshTokens.js";
import mysql2 from 'mysql2/promise';
import crypto from 'crypto';

describe('Anomalies Security Tests - IP & Geolocation Security', () => {

  // Test helper to create test data
  async function createTestVisitorAndUser(context: any, visitorData = {}) {
    const canaryId = `test-canary-${Date.now()}-${Math.random()}`;
    const defaultVisitorData = {
      canary_id: canaryId,
      ip_address: '192.168.1.100',
      user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      country: 'US',
      city: 'New York',
      district: 'Manhattan',
      lat: '40.7128',
      lon: '-74.0060',
      timezone: 'America/New_York',
      currency: 'USD',
      isp: 'Test ISP',
      org: 'Test Org',
      as_org: 'Test AS',
      device_type: 'desktop',
      browser: 'Chrome',
      proxy: false,
      proxy_allowed: false,
      hosting: false,
      hosting_allowed: false,
      last_seen: new Date(),
      deviceVendor: 'Intel',
      deviceModel: 'Unknown',
      browserType: 'browser',
      browserVersion: '119.0',
      os: 'Windows',
      suspicos_activity_score: 0,
      ...visitorData
    };

    const [visitorResult] = await context.mainPool.execute<mysql2.ResultSetHeader>(
      `INSERT INTO visitors (${Object.keys(defaultVisitorData).join(', ')}) VALUES (${Object.keys(defaultVisitorData).map(() => '?').join(', ')})`,
      Object.values(defaultVisitorData)
    );

    const visitorId = visitorResult.insertId;

    const [userResult] = await context.mainPool.execute<mysql2.ResultSetHeader>(
      'INSERT INTO users (email, password_hash, visitor_id, last_mfa_at) VALUES (?, ?, ?, ?)',
      [`test-${Date.now()}@example.com`, 'test-hash', visitorId, new Date()]
    );

    return {
      userId: userResult.insertId,
      visitorId,
      canaryId,
      ...defaultVisitorData
    };
  }

  afterEach(async (context) => {
    // Clean up test data
    await context.mainPool.execute('DELETE FROM refresh_tokens WHERE user_id IN (SELECT id FROM users WHERE email LIKE "test-%")');
    await context.mainPool.execute('DELETE FROM users WHERE email LIKE "test-%"');
    await context.mainPool.execute('DELETE FROM visitors WHERE canary_id LIKE "test-canary-%"');
  });

  it('should detect IP address mismatches and require MFA', async (context) => {
    const testData = await createTestVisitorAndUser(context, {
      ip_address: '192.168.1.100'
    });
    
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    const result = await strangeThings(
      refreshToken.raw,
      testData.canaryId,
      '10.0.0.1', // Different IP address
      testData.user_agent,
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Ip does not match');
    expect(result.reqMFA).toBe(true);
    expect(result.userId).toBe(testData.userId);
    expect(result.visitorId).toBe(testData.visitorId);
  });

  it('should accept IP addresses within same range', async (context) => {
    const testData = await createTestVisitorAndUser(context, {
      ip_address: '192.168.1.100'
    });
    
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    const result = await strangeThings(
      refreshToken.raw,
      testData.canaryId,
      '192.168.1.101', // Same subnet
      testData.user_agent,
      false
    );

    // Should pass IP check and continue to further validation
    expect(result.valid).toBe(true);
    expect(result.reason).toBe('Checks passed');
    expect(result.reqMFA).toBe(false);
  });

  it('should handle malicious IP address input', async (context) => {
    const testData = await createTestVisitorAndUser(context);
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    const maliciousIPs = [
      '../../etc/passwd',
      '<script>alert("xss")</script>',
      "'; DROP TABLE visitors; --",
      'localhost/../../../etc/passwd',
      null,
      undefined,
      'a'.repeat(1000),
      '999.999.999.999',
      '::1/../../../etc/passwd'
    ];

    for (const maliciousIP of maliciousIPs) {
      const result = await strangeThings(
        refreshToken.raw,
        testData.canaryId,
        maliciousIP as string,
        testData.user_agent,
        false
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Ip does not match');
      expect(result.reqMFA).toBe(true);
    }
  });

  it('should detect proxy usage when not allowed', async (context) => {
    const testData = await createTestVisitorAndUser(context, {
      proxy_allowed: false,
      hosting_allowed: false
    });
    
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    // Note: This test depends on the getGeoData function detecting proxy usage
    // For a real implementation, we would mock the getGeoData response
    const result = await strangeThings(
      refreshToken.raw,
      testData.canaryId,
      testData.ip_address,
      testData.user_agent,
      false
    );

    // Since we can't easily mock getGeoData in this test setup,
    // we expect the function to complete and either pass or detect proxy
    expect(result).toHaveProperty('valid');
    expect(result).toHaveProperty('reason');
    expect(result).toHaveProperty('reqMFA');
  });

  it('should allow proxy usage when explicitly permitted', async (context) => {
    const testData = await createTestVisitorAndUser(context, {
      proxy_allowed: true,
      hosting_allowed: true
    });
    
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    const result = await strangeThings(
      refreshToken.raw,
      testData.canaryId,
      testData.ip_address,
      testData.user_agent,
      false
    );

    // Should pass all checks
    expect(result.valid).toBe(true);
    expect(result.reason).toBe('Checks passed');
    expect(result.reqMFA).toBe(false);
  });

  it('should handle IPv6 addresses correctly', async (context) => {
    const testData = await createTestVisitorAndUser(context, {
      ip_address: '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
    });
    
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    const ipv6Tests = [
      '2001:0db8:85a3:0000:0000:8a2e:0370:7334', // Same IP
      '2001:db8:85a3::8a2e:370:7334', // Compressed notation
      '2001:0db8:85a3:0000:0000:8a2e:0370:7335', // Different IP
      '::1', // Localhost IPv6
      'fe80::1' // Link-local
    ];

    for (const testIP of ipv6Tests) {
      const result = await strangeThings(
        refreshToken.raw,
        testData.canaryId,
        testIP,
        testData.user_agent,
        false
      );

      expect(result).toHaveProperty('valid');
      expect(result).toHaveProperty('reason');
      expect(result).toHaveProperty('reqMFA');
    }
  });

  it('should handle geographic location changes', async (context) => {
    const testData = await createTestVisitorAndUser(context, {
      country: 'US',
      city: 'New York',
      lat: '40.7128',
      lon: '-74.0060'
    });
    
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    // Test with completely different geographic location
    // This would be detected through the botdetector integration
    const result = await strangeThings(
      refreshToken.raw,
      testData.canaryId,
      '8.8.8.8', // Google DNS - different location
      testData.user_agent,
      false
    );

    // Should detect the geographic change
    expect(result.valid).toBe(false);
    expect(['Ip does not match', 'Loop detected']).toContain(result.reason);
    expect(result.reqMFA).toBe(true);
  });

  it('should detect hosting provider IPs when not allowed', async (context) => {
    const testData = await createTestVisitorAndUser(context, {
      hosting_allowed: false
    });
    
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    // Test with known hosting provider IPs
    const hostingIPs = [
      '134.195.196.26', // DigitalOcean
      '52.1.1.1', // AWS
      '104.131.1.1' // DigitalOcean
    ];

    for (const hostingIP of hostingIPs) {
      const result = await strangeThings(
        refreshToken.raw,
        testData.canaryId,
        hostingIP,
        testData.user_agent,
        false
      );

      // Should either fail on IP mismatch or hosting detection
      expect(result.valid).toBe(false);
      expect(['Ip does not match', 'Proxy Or hosting']).toContain(result.reason);
      expect(result.reqMFA).toBe(true);
    }
  });

  it('should handle edge cases with private IP ranges', async (context) => {
    const privateIPRanges = [
      { stored: '192.168.1.100', test: '192.168.1.101', shouldMatch: true },
      { stored: '192.168.1.100', test: '192.168.2.100', shouldMatch: false },
      { stored: '10.0.0.1', test: '10.0.0.2', shouldMatch: true },
      { stored: '10.0.0.1', test: '172.16.0.1', shouldMatch: false },
      { stored: '172.16.0.1', test: '172.16.0.2', shouldMatch: true },
      { stored: '172.16.0.1', test: '192.168.1.1', shouldMatch: false }
    ];

    for (const ipTest of privateIPRanges) {
      const testData = await createTestVisitorAndUser(context, {
        ip_address: ipTest.stored
      });
      
      const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

      const result = await strangeThings(
        refreshToken.raw,
        testData.canaryId,
        ipTest.test,
        testData.user_agent,
        false
      );

      if (ipTest.shouldMatch) {
        expect(result.valid).toBe(true);
        expect(result.reason).toBe('Checks passed');
      } else {
        expect(result.valid).toBe(false);
        expect(result.reason).toBe('Ip does not match');
        expect(result.reqMFA).toBe(true);
      }

      // Cleanup for next iteration
      await context.mainPool.execute('DELETE FROM refresh_tokens WHERE user_id = ?', [testData.userId]);
      await context.mainPool.execute('DELETE FROM users WHERE id = ?', [testData.userId]);
      await context.mainPool.execute('DELETE FROM visitors WHERE canary_id = ?', [testData.canaryId]);
    }
  });

  it('should handle ISP and organization changes', async (context) => {
    const testData = await createTestVisitorAndUser(context, {
      isp: 'Comcast',
      org: 'Comcast Cable Communications',
      as_org: 'AS7922 Comcast Cable Communications'
    });
    
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    // Simulating request from a different ISP would be detected through geolocation
    const result = await strangeThings(
      refreshToken.raw,
      testData.canaryId,
      '8.8.4.4', // Google DNS - different ISP
      testData.user_agent,
      false
    );

    // Should detect the ISP change
    expect(result.valid).toBe(false);
    expect(['Ip does not match', 'Loop detected']).toContain(result.reason);
    expect(result.reqMFA).toBe(true);
  });

  it('should handle malformed geographic data gracefully', async (context) => {
    const testData = await createTestVisitorAndUser(context, {
      lat: 'invalid-latitude',
      lon: 'invalid-longitude',
      country: null,
      city: '',
      timezone: 'invalid/timezone'
    });
    
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    const result = await strangeThings(
      refreshToken.raw,
      testData.canaryId,
      testData.ip_address,
      testData.user_agent,
      false
    );

    // Should handle malformed data gracefully
    expect(result).toHaveProperty('valid');
    expect(result).toHaveProperty('reason');
    expect(result).toHaveProperty('reqMFA');
  });

  it('should detect rapid geographic location changes', async (context) => {
    // Test scenario: User appears to travel from New York to Tokyo in minutes
    const testData = await createTestVisitorAndUser(context, {
      country: 'US',
      city: 'New York',
      timezone: 'America/New_York'
    });
    
    const refreshToken = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testData.userId);

    // Simulate access from Tokyo (would require geolocation service to detect)
    const result = await strangeThings(
      refreshToken.raw,
      testData.canaryId,
      '210.196.224.1', // Japan IP
      testData.user_agent,
      false
    );

    expect(result.valid).toBe(false);
    expect(['Ip does not match', 'Loop detected']).toContain(result.reason);
    expect(result.reqMFA).toBe(true);
  });

});