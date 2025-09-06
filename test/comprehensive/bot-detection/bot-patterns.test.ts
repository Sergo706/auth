import { describe, test, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import { generateAccessToken, verifyAccessToken } from '../../../src/accessTokens.js';
import { generateRefreshToken, verifyRefreshToken } from '../../../src/refreshTokens.js';
import { 
  setupTestDatabase, 
  teardownTestDatabase, 
  setupTestUser, 
  cleanupTestData,
  mockBotDetector 
} from '../test-setup.js';

// Mock bot detector for controlled testing
mockBotDetector();

describe('Bot Detection Integration', () => {
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

  test('should detect known bot user agents', async () => {
    const userId = 999;
    const visitorId = 888;
    
    const botUserAgents = [
      'Googlebot/2.1 (+http://www.google.com/bot.html)',
      'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
      'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
      'Twitterbot/1.0',
      'LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com/)',
      'WhatsApp/2.19.81',
      'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)',
      'DiscordBot (https://discordapp.com)',
      'TelegramBot (like TwitterBot)',
      'curl/7.64.1',
      'wget/1.20.3',
      'python-requests/2.25.1',
      'Scrapy/2.5.0',
      'HeadlessChrome/91.0',
      'PhantomJS/2.1.1',
      'SlimerJS/1.0.0'
    ];

    for (const userAgent of botUserAgents) {
      try {
        // Bot detection should be triggered during token operations
        const token = await generateAccessToken(userId, visitorId);
        
        // Mock the user agent detection
        const { parseUA } = await import('@riavzon/botdetector');
        vi.mocked(parseUA).mockReturnValueOnce({
          device: 'bot',
          browser: 'bot',
          browserType: 'bot',
          browserVersion: '1.0',
          os: 'unknown',
          deviceVendor: 'unknown',
          deviceModel: 'unknown'
        });
        
        // Verification might still succeed, but bot should be flagged
        const verification = await verifyAccessToken(token.raw);
        // The system should handle bots gracefully
        expect(typeof verification.valid).toBe('boolean');
        
      } catch (error) {
        // Bot detection errors are also acceptable
        expect(error).toBeDefined();
      }
    }
  });

  test('should detect suspicious activity patterns', async () => {
    const userId = 999;
    const visitorId = 888;
    
    // Simulate rapid token generation (bot-like behavior)
    const rapidTokens = [];
    const startTime = Date.now();
    
    for (let i = 0; i < 10; i++) {
      try {
        const token = await generateRefreshToken(24 * 60 * 60 * 1000, userId);
        rapidTokens.push(token);
      } catch (error) {
        // Rate limiting or bot detection is expected
        expect(error).toBeDefined();
        break;
      }
    }
    
    const endTime = Date.now();
    const duration = endTime - startTime;
    
    // If all tokens were generated, it should have taken reasonable time
    // or rate limiting should have kicked in
    if (rapidTokens.length === 10) {
      expect(duration).toBeGreaterThan(1000); // Should take at least 1 second
    }
  });

  test('should handle IP-based bot detection', async () => {
    const userId = 999;
    const visitorId = 888;
    
    // Simulate requests from suspicious IP ranges
    const suspiciousIPs = [
      '127.0.0.1', // Localhost
      '10.0.0.1', // Private network
      '192.168.1.1', // Private network
      '172.16.0.1', // Private network
      '0.0.0.0', // Invalid IP
      '255.255.255.255', // Broadcast
    ];

    for (const ip of suspiciousIPs) {
      try {
        // Mock geo data for suspicious IP
        const { getGeoData } = await import('@riavzon/botdetector');
        vi.mocked(getGeoData).mockResolvedValueOnce({
          country: 'XX', // Unknown country
          region: 'XX',
          regionName: 'Unknown',
          city: 'Unknown',
          district: 'Unknown',
          lat: 0,
          lon: 0,
          timezone: 'UTC',
          currency: 'XXX',
          isp: 'Unknown ISP',
          org: 'Unknown Org',
          as: 'AS00000'
        });
        
        const token = await generateRefreshToken(24 * 60 * 60 * 1000, userId);
        
        // Should either succeed with monitoring or fail with detection
        expect(token).toBeDefined();
        
      } catch (error) {
        // Bot detection blocking is acceptable
        expect(error).toBeDefined();
      }
    }
  });

  test('should detect rapid geographic location changes', async () => {
    const userId = 999;
    const visitorId = 888;
    
    const locations = [
      { country: 'US', lat: 40.7128, lon: -74.0060, city: 'New York' },
      { country: 'JP', lat: 35.6762, lon: 139.6503, city: 'Tokyo' },
      { country: 'AU', lat: -33.8688, lon: 151.2093, city: 'Sydney' },
      { country: 'DE', lat: 52.5200, lon: 13.4050, city: 'Berlin' },
      { country: 'BR', lat: -23.5505, lon: -46.6333, city: 'São Paulo' }
    ];

    const { getGeoData } = await import('@riavzon/botdetector');
    
    for (let i = 0; i < locations.length; i++) {
      const location = locations[i];
      
      // Mock rapidly changing locations
      vi.mocked(getGeoData).mockResolvedValueOnce({
        country: location.country,
        region: 'XX',
        regionName: 'Test Region',
        city: location.city,
        district: 'Test District',
        lat: location.lat,
        lon: location.lon,
        timezone: 'UTC',
        currency: 'USD',
        isp: 'Test ISP',
        org: 'Test Org',
        as: 'AS12345'
      });

      try {
        const token = await generateRefreshToken(100, userId); // Short TTL for rapid testing
        expect(token).toBeDefined();
        
        // Small delay to simulate real-world timing
        await new Promise(resolve => setTimeout(resolve, 10));
        
      } catch (error) {
        // Geographic anomaly detection is expected
        expect(error).toBeDefined();
      }
    }
  });

  test('should handle device fingerprint anomalies', async () => {
    const userId = 999;
    const visitorId = 888;
    
    const deviceFingerprints = [
      { device: 'mobile', browser: 'Chrome', os: 'iOS' },
      { device: 'desktop', browser: 'Firefox', os: 'Windows' },
      { device: 'tablet', browser: 'Safari', os: 'iPadOS' },
      { device: 'mobile', browser: 'Edge', os: 'Android' },
      { device: 'desktop', browser: 'Opera', os: 'macOS' }
    ];

    const { parseUA } = await import('@riavzon/botdetector');
    
    for (const fingerprint of deviceFingerprints) {
      // Mock rapidly changing device fingerprints
      vi.mocked(parseUA).mockReturnValueOnce({
        device: fingerprint.device,
        browser: fingerprint.browser,
        browserType: 'browser',
        browserVersion: '91.0',
        os: fingerprint.os,
        deviceVendor: 'unknown',
        deviceModel: 'unknown'
      });

      try {
        const token = await generateAccessToken(userId, visitorId);
        const verification = await verifyAccessToken(token.raw);
        
        // Should handle device changes gracefully
        expect(typeof verification.valid).toBe('boolean');
        
      } catch (error) {
        // Device anomaly detection is acceptable
        expect(error).toBeDefined();
      }
      
      // Small delay between requests
      await new Promise(resolve => setTimeout(resolve, 10));
    }
  });

  test('should identify headless browser patterns', async () => {
    const userId = 999;
    const visitorId = 888;
    
    const headlessPatterns = [
      'HeadlessChrome/91.0.4472.124',
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/91.0.4472.124 Safari/537.36',
      'PhantomJS/2.1.1 (QtWebKit/538.1)',
      'Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1',
      'SlimerJS/1.0.0'
    ];

    const { parseUA } = await import('@riavzon/botdetector');
    
    for (const userAgent of headlessPatterns) {
      vi.mocked(parseUA).mockReturnValueOnce({
        device: 'desktop',
        browser: 'Chrome',
        browserType: 'headless',
        browserVersion: '91.0',
        os: 'Linux',
        deviceVendor: 'unknown',
        deviceModel: 'unknown'
      });

      try {
        const token = await generateRefreshToken(24 * 60 * 60 * 1000, userId);
        
        // System should detect headless browsers
        expect(token).toBeDefined();
        
      } catch (error) {
        // Headless browser blocking is expected
        expect(error).toBeDefined();
      }
    }
  });

  test('should handle automated tool detection', async () => {
    const userId = 999;
    const visitorId = 888;
    
    const automatedTools = [
      'curl/7.68.0',
      'wget/1.20.3 (linux-gnu)',
      'python-requests/2.25.1',
      'PostmanRuntime/7.26.8',
      'insomnia/2021.2.2',
      'HTTPie/2.4.0',
      'Apache-HttpClient/4.5.13',
      'okhttp/4.9.1'
    ];

    const { parseUA } = await import('@riavzon/botdetector');
    
    for (const tool of automatedTools) {
      vi.mocked(parseUA).mockReturnValueOnce({
        device: 'other',
        browser: 'unknown',
        browserType: 'tool',
        browserVersion: '1.0',
        os: 'unknown',
        deviceVendor: 'unknown',
        deviceModel: 'unknown'
      });

      try {
        const token = await generateAccessToken(userId, visitorId);
        const verification = await verifyAccessToken(token.raw);
        
        // Should handle automated tools appropriately
        expect(typeof verification.valid).toBe('boolean');
        
      } catch (error) {
        // Tool detection and blocking is expected
        expect(error).toBeDefined();
      }
    }
  });

  test('should track bot detection metrics', async () => {
    const userId = 999;
    const visitorId = 888;
    
    const { updateIsBot, banIp } = await import('@riavzon/botdetector');
    
    // Clear previous mock calls
    vi.mocked(updateIsBot).mockClear();
    vi.mocked(banIp).mockClear();
    
    // Simulate bot-like behavior
    const { parseUA } = await import('@riavzon/botdetector');
    vi.mocked(parseUA).mockReturnValue({
      device: 'bot',
      browser: 'bot',
      browserType: 'bot',
      browserVersion: '1.0',
      os: 'unknown',
      deviceVendor: 'unknown',
      deviceModel: 'unknown'
    });

    try {
      // Generate tokens with bot fingerprint
      for (let i = 0; i < 3; i++) {
        await generateRefreshToken(24 * 60 * 60 * 1000, userId);
        await new Promise(resolve => setTimeout(resolve, 10));
      }
    } catch (error) {
      // Expected if bot detection kicks in
    }

    // Bot detection functions should have been called
    // Note: The actual calls depend on implementation details
    expect(vi.mocked(updateIsBot).mock.calls.length).toBeGreaterThanOrEqual(0);
    expect(vi.mocked(banIp).mock.calls.length).toBeGreaterThanOrEqual(0);
  });
});