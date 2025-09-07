import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { strangeThings } from '../../src/anomalies.js';
import { generateRefreshToken } from '../../src/refreshTokens.js';

// Mock the botdetector module for predictable testing
vi.mock('@riavzon/botdetector', () => ({
  getGeoData: vi.fn().mockResolvedValue({
    proxy: false,
    hosting: false,
    country: 'US',
    city: 'New York',
    isp: 'Test ISP',
    org: 'Test Organization',
    as_org: 'Test AS'
  }),
  parseUA: vi.fn().mockReturnValue({
    device: 'desktop',
    browser: 'Chrome',
    browserType: 'browser',
    browserVersion: '120.0.0',
    os: 'Windows',
    deviceVendor: 'Dell',
    deviceModel: 'Laptop'
  })
}));

describe('Anomalies - Device Fingerprinting', () => {
  let testUserId: number;
  let validToken: string;
  let canaryId: string;

  beforeEach(async (context) => {
    testUserId = context.testUserId;
    
    // Get canary ID
    const [visitorRows] = await context.mainPool.execute<any[]>(
      'SELECT v.canary_id FROM visitors v JOIN users u ON v.visitor_id = u.visitor_id WHERE u.id = ?',
      [testUserId]
    );
    canaryId = visitorRows[0].canary_id;

    // Generate valid token (7 days TTL)
    const tokenResult = await generateRefreshToken(7 * 24 * 60 * 60 * 1000, testUserId);
    validToken = tokenResult.raw;

    // Set up known good visitor data
    await context.mainPool.execute(`
      UPDATE visitors v 
      JOIN users u ON v.visitor_id = u.visitor_id 
      SET v.country = 'US',
          v.city = 'New York',
          v.isp = 'Test ISP',
          v.org = 'Test Organization',
          v.as_org = 'Test AS',
          v.device_type = 'desktop',
          v.browser = 'Chrome',
          v.browserType = 'browser',
          v.browserVersion = '120.0.0',
          v.os = 'Windows',
          v.deviceVendor = 'Dell',
          v.deviceModel = 'Laptop',
          v.suspicos_activity_score = 0,
          v.proxy = FALSE,
          v.hosting = FALSE
      WHERE u.id = ?
    `, [testUserId]);
  });

  afterEach(async (context) => {
    await context.mainPool.execute('DELETE FROM refresh_tokens WHERE user_id = ?', [testUserId]);
    vi.resetAllMocks();
  });

  it('should trigger MFA when device type changes', async () => {
    // Mock different device type
    const { parseUA } = await import('@riavzon/botdetector');
    vi.mocked(parseUA).mockReturnValueOnce({
      device: 'mobile', // Changed from desktop
      browser: 'Chrome',
      browserType: 'browser',
      browserVersion: '120.0.0',
      os: 'Windows',
      deviceVendor: 'Dell',
      deviceModel: 'Laptop'
    });

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Mobile Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Loop detected');
    expect(result.reqMFA).toBe(true);
    expect(result.userId).toBe(testUserId);
  });

  it('should trigger MFA when browser changes', async () => {
    // Mock different browser
    const { parseUA } = await import('@riavzon/botdetector');
    vi.mocked(parseUA).mockReturnValueOnce({
      device: 'desktop',
      browser: 'Firefox', // Changed from Chrome
      browserType: 'browser',
      browserVersion: '120.0.0',
      os: 'Windows',
      deviceVendor: 'Dell',
      deviceModel: 'Laptop'
    });

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Firefox)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Loop detected');
    expect(result.reqMFA).toBe(true);
  });

  it('should trigger MFA when operating system changes', async () => {
    // Mock different OS
    const { parseUA } = await import('@riavzon/botdetector');
    vi.mocked(parseUA).mockReturnValueOnce({
      device: 'desktop',
      browser: 'Chrome',
      browserType: 'browser',
      browserVersion: '120.0.0',
      os: 'macOS', // Changed from Windows
      deviceVendor: 'Dell',
      deviceModel: 'Laptop'
    });

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Macintosh)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Loop detected');
    expect(result.reqMFA).toBe(true);
  });

  it('should trigger MFA when country changes', async () => {
    // Mock different country
    const { getGeoData } = await import('@riavzon/botdetector');
    vi.mocked(getGeoData).mockResolvedValueOnce({
      proxy: false,
      hosting: false,
      country: 'CA', // Changed from US
      city: 'New York',
      isp: 'Test ISP',
      org: 'Test Organization',
      as_org: 'Test AS'
    });

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Loop detected');
    expect(result.reqMFA).toBe(true);
  });

  it('should trigger MFA when city changes', async () => {
    // Mock different city
    const { getGeoData } = await import('@riavzon/botdetector');
    vi.mocked(getGeoData).mockResolvedValueOnce({
      proxy: false,
      hosting: false,
      country: 'US',
      city: 'Los Angeles', // Changed from New York
      isp: 'Test ISP',
      org: 'Test Organization',
      as_org: 'Test AS'
    });

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Loop detected');
    expect(result.reqMFA).toBe(true);
  });

  it('should allow requests when all device characteristics match', async () => {
    // Mock exact same data as stored
    const { getGeoData, parseUA } = await import('@riavzon/botdetector');
    
    vi.mocked(getGeoData).mockResolvedValueOnce({
      proxy: false,
      hosting: false,
      country: 'US',
      city: 'New York',
      isp: 'Test ISP',
      org: 'Test Organization',
      as_org: 'Test AS'
    });

    vi.mocked(parseUA).mockReturnValueOnce({
      device: 'desktop',
      browser: 'Chrome',
      browserType: 'browser',
      browserVersion: '120.0.0',
      os: 'Windows',
      deviceVendor: 'Dell',
      deviceModel: 'Laptop'
    });

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(true);
    expect(result.reason).toBe('Checks passed');
    expect(result.reqMFA).toBe(false);
  });

  it('should ignore undefined/null values in fingerprinting', async (context) => {
    // Set some stored values to null/unknown
    await context.mainPool.execute(`
      UPDATE visitors v 
      JOIN users u ON v.visitor_id = u.visitor_id 
      SET v.deviceVendor = 'unknown',
          v.deviceModel = NULL
      WHERE u.id = ?
    `, [testUserId]);

    // Mock incoming values as null/undefined
    const { parseUA } = await import('@riavzon/botdetector');
    vi.mocked(parseUA).mockReturnValueOnce({
      device: 'desktop',
      browser: 'Chrome',
      browserType: 'browser',
      browserVersion: '120.0.0',
      os: 'Windows',
      deviceVendor: undefined,
      deviceModel: null
    } as any);

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    // Should not trigger loop detection for null/undefined/unknown values
    expect(result.reason).not.toBe('Loop detected');
    expect(result.userId).toBe(testUserId);
  });

  it('should ignore unknown values in fingerprinting', async (context) => {
    // Mock incoming values as unknown
    const { parseUA } = await import('@riavzon/botdetector');
    vi.mocked(parseUA).mockReturnValueOnce({
      device: 'desktop',
      browser: 'Chrome',
      browserType: 'browser',
      browserVersion: '120.0.0',
      os: 'Windows',
      deviceVendor: 'unknown', // Should be ignored
      deviceModel: 'unknown'   // Should be ignored
    });

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    // Should not trigger loop detection for unknown values
    expect(result.reason).not.toBe('Loop detected');
    expect(result.userId).toBe(testUserId);
  });

  it('should handle multiple mismatched characteristics', async () => {
    // Mock multiple different characteristics
    const { getGeoData, parseUA } = await import('@riavzon/botdetector');
    
    vi.mocked(getGeoData).mockResolvedValueOnce({
      proxy: false,
      hosting: false,
      country: 'CA',           // Different
      city: 'Toronto',         // Different
      isp: 'Different ISP',    // Different
      org: 'Different Org',    // Different
      as_org: 'Different AS'   // Different
    });

    vi.mocked(parseUA).mockReturnValueOnce({
      device: 'mobile',        // Different
      browser: 'Safari',       // Different
      browserType: 'browser',
      browserVersion: '15.0.0', // Different
      os: 'iOS',               // Different
      deviceVendor: 'Apple',   // Different
      deviceModel: 'iPhone'    // Different
    });

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (iPhone)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Loop detected');
    expect(result.reqMFA).toBe(true);
  });

  it('should handle empty string values', async (context) => {
    // Set stored values to empty strings
    await context.mainPool.execute(`
      UPDATE visitors v 
      JOIN users u ON v.visitor_id = u.visitor_id 
      SET v.deviceVendor = '',
          v.deviceModel = ''
      WHERE u.id = ?
    `, [testUserId]);

    // Mock incoming empty values
    const { parseUA } = await import('@riavzon/botdetector');
    vi.mocked(parseUA).mockReturnValueOnce({
      device: 'desktop',
      browser: 'Chrome',
      browserType: 'browser',
      browserVersion: '120.0.0',
      os: 'Windows',
      deviceVendor: '',
      deviceModel: ''
    });

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    // Empty strings should not trigger mismatch
    expect(result.reason).not.toBe('Loop detected');
    expect(result.userId).toBe(testUserId);
  });

  it('should handle case sensitivity in string comparisons', async (context) => {
    // Mock different case
    const { parseUA } = await import('@riavzon/botdetector');
    vi.mocked(parseUA).mockReturnValueOnce({
      device: 'desktop',
      browser: 'chrome',       // lowercase vs Chrome
      browserType: 'browser',
      browserVersion: '120.0.0',
      os: 'windows',          // lowercase vs Windows
      deviceVendor: 'dell',   // lowercase vs Dell
      deviceModel: 'laptop'   // lowercase vs Laptop
    });

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    // Case differences should trigger mismatch
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Loop detected');
    expect(result.reqMFA).toBe(true);
  });
});