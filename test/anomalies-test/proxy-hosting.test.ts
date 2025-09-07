import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { strangeThings } from '../../src/anomalies.js';
import { generateRefreshToken } from '../../src/refreshTokens.js';

// Mock the botdetector module for predictable testing
vi.mock('@riavzon/botdetector', () => ({
  getGeoData: vi.fn().mockResolvedValue({
    proxy: false,
    hosting: false,
    country: 'US',
    city: 'Test City',
    isp: 'Test ISP',
    org: 'Test Org',
    as_org: 'Test AS'
  }),
  parseUA: vi.fn().mockReturnValue({
    device: 'desktop',
    browser: 'Chrome',
    browserType: 'browser',
    browserVersion: '120.0.0',
    os: 'Windows',
    deviceVendor: 'unknown',
    deviceModel: 'unknown'
  })
}));

describe('Anomalies - Proxy and Hosting Detection', () => {
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
  });

  afterEach(async (context) => {
    await context.mainPool.execute('DELETE FROM refresh_tokens WHERE user_id = ?', [testUserId]);
    vi.resetAllMocks();
  });

  it('should trigger MFA when proxy detected and not allowed', async (context) => {
    // Mock geo data to show proxy
    const { getGeoData } = await import('@riavzon/botdetector');
    vi.mocked(getGeoData).mockResolvedValueOnce({
      proxy: true,
      hosting: false,
      country: 'US',
      city: 'Test City',
      isp: 'Proxy ISP',
      org: 'Proxy Org',
      as_org: 'Proxy AS'
    });

    // Ensure proxy is not allowed for this user
    await context.mainPool.execute(
      'UPDATE visitors v JOIN users u ON v.visitor_id = u.visitor_id SET v.proxy_allowed = FALSE WHERE u.id = ?',
      [testUserId]
    );

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Proxy Or hosting');
    expect(result.reqMFA).toBe(true);
    expect(result.userId).toBe(testUserId);
  });

  it('should trigger MFA when hosting detected and not allowed', async (context) => {
    // Mock geo data to show hosting
    const { getGeoData } = await import('@riavzon/botdetector');
    vi.mocked(getGeoData).mockResolvedValueOnce({
      proxy: false,
      hosting: true,
      country: 'US',
      city: 'Test City',
      isp: 'Cloud Provider',
      org: 'AWS',
      as_org: 'Amazon'
    });

    // Ensure hosting is not allowed for this user
    await context.mainPool.execute(
      'UPDATE visitors v JOIN users u ON v.visitor_id = u.visitor_id SET v.hosting_allowed = FALSE WHERE u.id = ?',
      [testUserId]
    );

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Proxy Or hosting');
    expect(result.reqMFA).toBe(true);
    expect(result.userId).toBe(testUserId);
  });

  it('should allow proxy when proxy_allowed is true', async (context) => {
    // Mock geo data to show proxy
    const { getGeoData } = await import('@riavzon/botdetector');
    vi.mocked(getGeoData).mockResolvedValueOnce({
      proxy: true,
      hosting: false,
      country: 'US',
      city: 'Test City',
      isp: 'Proxy ISP',
      org: 'Proxy Org',
      as_org: 'Proxy AS'
    });

    // Allow proxy for this user
    await context.mainPool.execute(
      'UPDATE visitors v JOIN users u ON v.visitor_id = u.visitor_id SET v.proxy_allowed = TRUE WHERE u.id = ?',
      [testUserId]
    );

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(true);
    expect(result.reason).toBe('Proxy or hosting allowed');
    expect(result.reqMFA).toBe(false);
  });

  it('should allow hosting when hosting_allowed is true', async (context) => {
    // Mock geo data to show hosting
    const { getGeoData } = await import('@riavzon/botdetector');
    vi.mocked(getGeoData).mockResolvedValueOnce({
      proxy: false,
      hosting: true,
      country: 'US',
      city: 'Test City',
      isp: 'Cloud Provider',
      org: 'AWS',
      as_org: 'Amazon'
    });

    // Allow hosting for this user
    await context.mainPool.execute(
      'UPDATE visitors v JOIN users u ON v.visitor_id = u.visitor_id SET v.hosting_allowed = TRUE WHERE u.id = ?',
      [testUserId]
    );

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(true);
    expect(result.reason).toBe('Proxy or hosting allowed');
    expect(result.reqMFA).toBe(false);
  });

  it('should trigger MFA when both proxy and hosting detected but only one allowed', async (context) => {
    // Mock geo data to show both proxy and hosting
    const { getGeoData } = await import('@riavzon/botdetector');
    vi.mocked(getGeoData).mockResolvedValueOnce({
      proxy: true,
      hosting: true,
      country: 'US',
      city: 'Test City',
      isp: 'Cloud Proxy',
      org: 'Proxy Host',
      as_org: 'ProxyHost AS'
    });

    // Allow only proxy, not hosting
    await context.mainPool.execute(
      'UPDATE visitors v JOIN users u ON v.visitor_id = u.visitor_id SET v.proxy_allowed = TRUE, v.hosting_allowed = FALSE WHERE u.id = ?',
      [testUserId]
    );

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Proxy Or hosting');
    expect(result.reqMFA).toBe(true);
  });

  it('should allow when both proxy and hosting detected and both allowed', async (context) => {
    // Mock geo data to show both proxy and hosting
    const { getGeoData } = await import('@riavzon/botdetector');
    vi.mocked(getGeoData).mockResolvedValueOnce({
      proxy: true,
      hosting: true,
      country: 'US',
      city: 'Test City',
      isp: 'Cloud Proxy',
      org: 'Proxy Host',
      as_org: 'ProxyHost AS'
    });

    // Allow both proxy and hosting
    await context.mainPool.execute(
      'UPDATE visitors v JOIN users u ON v.visitor_id = u.visitor_id SET v.proxy_allowed = TRUE, v.hosting_allowed = TRUE WHERE u.id = ?',
      [testUserId]
    );

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    expect(result.valid).toBe(true);
    expect(result.reason).toBe('Proxy or hosting allowed');
    expect(result.reqMFA).toBe(false);
  });

  it('should continue to device fingerprinting when no proxy/hosting detected', async () => {
    // Mock geo data with no proxy/hosting
    const { getGeoData } = await import('@riavzon/botdetector');
    vi.mocked(getGeoData).mockResolvedValueOnce({
      proxy: false,
      hosting: false,
      country: 'US',
      city: 'Test City',
      isp: 'Regular ISP',
      org: 'Regular Org',
      as_org: 'Regular AS'
    });

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    // Should proceed to device fingerprinting checks
    expect(result.reason).not.toBe('Proxy Or hosting');
    expect(result.userId).toBe(testUserId);
  });

  it('should handle null proxy/hosting flags', async (context) => {
    // Mock geo data with null values
    const { getGeoData } = await import('@riavzon/botdetector');
    vi.mocked(getGeoData).mockResolvedValueOnce({
      proxy: null,
      hosting: null,
      country: 'US',
      city: 'Test City',
      isp: 'Unknown ISP',
      org: 'Unknown Org',
      as_org: 'Unknown AS'
    } as any);

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    // Null values should be treated as false
    expect(result.reason).not.toBe('Proxy Or hosting');
    expect(result.userId).toBe(testUserId);
  });

  it('should handle undefined proxy/hosting flags', async (context) => {
    // Mock geo data with undefined values
    const { getGeoData } = await import('@riavzon/botdetector');
    vi.mocked(getGeoData).mockResolvedValueOnce({
      country: 'US',
      city: 'Test City',
      isp: 'Unknown ISP',
      org: 'Unknown Org',
      as_org: 'Unknown AS'
    } as any);

    const result = await strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    );

    // Undefined values should be treated as false
    expect(result.reason).not.toBe('Proxy Or hosting');
    expect(result.userId).toBe(testUserId);
  });

  it('should handle geo data fetch errors', async () => {
    // Mock geo data to throw error
    const { getGeoData } = await import('@riavzon/botdetector');
    vi.mocked(getGeoData).mockRejectedValueOnce(new Error('Geo data service unavailable'));

    // This should throw an error and not be caught by strangeThings
    await expect(strangeThings(
      validToken,
      canaryId,
      '127.0.0.1',
      'Mozilla/5.0 (Test Browser)',
      false
    )).rejects.toThrow('Geo data service unavailable');
  });
});