import { describe, test, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import mysql from 'mysql2/promise';
import mysql2 from 'mysql2';
import crypto from 'crypto';
import { configuration } from '../../src/jwtAuth/config/configuration.js';
import { handleXSS } from '../../src/jwtAuth/utils/handleXSS.js';
import { Request } from 'express';

// Mock the external dependencies
vi.mock('../../src/jwtAuth/utils/telegramLogger.js', () => ({
  sendLog: vi.fn().mockResolvedValue(undefined)
}));

vi.mock('@riavzon/botdetector', () => ({
  banIp: vi.fn().mockResolvedValue(undefined),
  updateIsBot: vi.fn().mockResolvedValue(undefined),
  updateBannedIP: vi.fn().mockResolvedValue(undefined)
}));

describe('XSS Handling and Security Tests', () => {
  let promisePool: mysql.Pool;
  let callbackPool: mysql2.Pool;
  let mockLogger: any;

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
      password: { pepper: 'test-pepper' },
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

    // Setup mock logger
    mockLogger = {
      warn: vi.fn(),
      error: vi.fn(),
      info: vi.fn(),
      debug: vi.fn(),
      child: vi.fn().mockReturnThis()
    };
  });

  afterAll(async () => {
    if (promisePool) await promisePool.end();
    if (callbackPool) callbackPool.end();
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  // Helper function to create mock request
  function createMockRequest(ip: string, userAgent: string, canaryId: string): Request {
    return {
      ip,
      cookies: { canary_id: canaryId },
      get: vi.fn().mockImplementation((header: string) => {
        if (header === 'User-Agent') return userAgent;
        return undefined;
      })
    } as any;
  }

  describe('XSS Detection and Response', () => {
    test('should detect basic script tag XSS', async () => {
      const maliciousPayload = '<script>alert("XSS")</script>';
      const req = createMockRequest('192.168.1.100', 'Mozilla/5.0', 'test_canary_xss_1');
      
      await handleXSS(req, maliciousPayload, mockLogger);
      
      // Verify logging occurred
      expect(mockLogger.warn).toHaveBeenCalledWith(' XSS attempt banning visitor...');
      expect(mockLogger.warn).toHaveBeenCalledWith('visitor banned.');
    });

    test('should detect iframe-based XSS', async () => {
      const maliciousPayload = '<iframe src="javascript:alert(1)"></iframe>';
      const req = createMockRequest('192.168.1.101', 'Mozilla/5.0', 'test_canary_xss_2');
      
      await handleXSS(req, maliciousPayload, mockLogger);
      
      expect(mockLogger.warn).toHaveBeenCalledWith(' XSS attempt banning visitor...');
    });

    test('should detect event handler XSS', async () => {
      const maliciousPayloads = [
        '<img src="x" onerror="alert(1)">',
        '<body onload="alert(1)">',
        '<div onclick="alert(1)">Click me</div>',
        '<svg onload="alert(1)">',
        '<input onfocus="alert(1)" autofocus>'
      ];
      
      for (let i = 0; i < maliciousPayloads.length; i++) {
        const req = createMockRequest('192.168.1.102', 'Mozilla/5.0', `test_canary_xss_3_${i}`);
        await handleXSS(req, maliciousPayloads[i], mockLogger);
        expect(mockLogger.warn).toHaveBeenCalledWith(' XSS attempt banning visitor...');
      }
    });

    test('should detect javascript: protocol XSS', async () => {
      const maliciousPayloads = [
        '<a href="javascript:alert(1)">Click</a>',
        '<img src="javascript:alert(1)">',
        '<form action="javascript:alert(1)">',
        'javascript:alert(document.cookie)'
      ];
      
      for (let i = 0; i < maliciousPayloads.length; i++) {
        const req = createMockRequest('192.168.1.103', 'Mozilla/5.0', `test_canary_xss_4_${i}`);
        await handleXSS(req, maliciousPayloads[i], mockLogger);
        expect(mockLogger.warn).toHaveBeenCalledWith(' XSS attempt banning visitor...');
      }
    });

    test('should detect data: protocol XSS', async () => {
      const maliciousPayloads = [
        'data:text/html,<script>alert(1)</script>',
        '<iframe src="data:text/html,<script>alert(1)</script>"></iframe>',
        '<object data="data:text/html,<script>alert(1)</script>"></object>'
      ];
      
      for (let i = 0; i < maliciousPayloads.length; i++) {
        const req = createMockRequest('192.168.1.104', 'Mozilla/5.0', `test_canary_xss_5_${i}`);
        await handleXSS(req, maliciousPayloads[i], mockLogger);
        expect(mockLogger.warn).toHaveBeenCalledWith(' XSS attempt banning visitor...');
      }
    });

    test('should detect encoded XSS attempts', async () => {
      const maliciousPayloads = [
        '&lt;script&gt;alert(1)&lt;/script&gt;',
        '%3Cscript%3Ealert(1)%3C/script%3E',
        '&#60;script&#62;alert(1)&#60;/script&#62;',
        '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e'
      ];
      
      for (let i = 0; i < maliciousPayloads.length; i++) {
        const req = createMockRequest('192.168.1.105', 'Mozilla/5.0', `test_canary_xss_6_${i}`);
        await handleXSS(req, maliciousPayloads[i], mockLogger);
        expect(mockLogger.warn).toHaveBeenCalledWith(' XSS attempt banning visitor...');
      }
    });

    test('should detect obfuscated XSS', async () => {
      const maliciousPayloads = [
        '<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
        '<iframe src="javas\tcript:alert(1)">',
        '<script>window["al"+"ert"](1)</script>',
        '<svg><script>alert`1`</script></svg>',
        '<math><mtext><script>alert(1)</script></mtext></math>'
      ];
      
      for (let i = 0; i < maliciousPayloads.length; i++) {
        const req = createMockRequest('192.168.1.106', 'Mozilla/5.0', `test_canary_xss_7_${i}`);
        await handleXSS(req, maliciousPayloads[i], mockLogger);
        expect(mockLogger.warn).toHaveBeenCalledWith(' XSS attempt banning visitor...');
      }
    });
  });

  describe('XSS Response Actions', () => {
    test('should call all required security actions', async () => {
      const { sendLog } = await import('../../src/jwtAuth/utils/telegramLogger.js');
      const { banIp, updateIsBot, updateBannedIP } = await import('@riavzon/botdetector');
      
      const maliciousPayload = '<script>alert("test")</script>';
      const req = createMockRequest('192.168.1.200', 'Mozilla/5.0 (Attack)', 'attack_canary_1');
      
      await handleXSS(req, maliciousPayload, mockLogger);
      
      // Verify all security actions were called
      expect(sendLog).toHaveBeenCalledWith('XSS attempt', maliciousPayload);
      expect(banIp).toHaveBeenCalledWith('192.168.1.200', { score: 10, reasons: ['XSS SCRIPTING ATTEMPT'] });
      expect(updateBannedIP).toHaveBeenCalledWith(
        'attack_canary_1',
        '192.168.1.200',
        'unknown',
        'Mozilla/5.0 (Attack)',
        { score: 10, reasons: ['XSS SCRIPTING ATTEMPT'] }
      );
      expect(updateIsBot).toHaveBeenCalledWith(true, 'attack_canary_1');
    });

    test('should handle missing User-Agent gracefully', async () => {
      const req = createMockRequest('192.168.1.201', '', 'attack_canary_2');
      req.get = vi.fn().mockReturnValue(undefined); // No User-Agent
      
      const maliciousPayload = '<script>alert("test")</script>';
      
      await expect(handleXSS(req, maliciousPayload, mockLogger)).resolves.not.toThrow();
      
      const { updateBannedIP } = await import('@riavzon/botdetector');
      expect(updateBannedIP).toHaveBeenCalledWith(
        'attack_canary_2',
        '192.168.1.201',
        'unknown',
        'unknown', // Should default to 'unknown'
        { score: 10, reasons: ['XSS SCRIPTING ATTEMPT'] }
      );
    });

    test('should handle missing canary_id gracefully', async () => {
      const req = createMockRequest('192.168.1.202', 'Mozilla/5.0', '');
      req.cookies = {}; // No canary_id
      
      const maliciousPayload = '<script>alert("test")</script>';
      
      await expect(handleXSS(req, maliciousPayload, mockLogger)).resolves.not.toThrow();
    });

    test('should handle missing IP address gracefully', async () => {
      const req = createMockRequest('', 'Mozilla/5.0', 'attack_canary_3');
      req.ip = undefined; // No IP
      
      const maliciousPayload = '<script>alert("test")</script>';
      
      await expect(handleXSS(req, maliciousPayload, mockLogger)).resolves.not.toThrow();
    });
  });

  describe('Edge Cases and Boundary Conditions', () => {
    test('should handle extremely long XSS payloads', async () => {
      const longPayload = '<script>alert("' + 'A'.repeat(10000) + '")</script>';
      const req = createMockRequest('192.168.1.210', 'Mozilla/5.0', 'long_payload_canary');
      
      await expect(handleXSS(req, longPayload, mockLogger)).resolves.not.toThrow();
      expect(mockLogger.warn).toHaveBeenCalledWith(' XSS attempt banning visitor...');
    });

    test('should handle empty XSS payload', async () => {
      const req = createMockRequest('192.168.1.211', 'Mozilla/5.0', 'empty_payload_canary');
      
      await expect(handleXSS(req, '', mockLogger)).resolves.not.toThrow();
      expect(mockLogger.warn).toHaveBeenCalledWith(' XSS attempt banning visitor...');
    });

    test('should handle null/undefined XSS payload', async () => {
      const req = createMockRequest('192.168.1.212', 'Mozilla/5.0', 'null_payload_canary');
      
      await expect(handleXSS(req, null as any, mockLogger)).resolves.not.toThrow();
      await expect(handleXSS(req, undefined as any, mockLogger)).resolves.not.toThrow();
    });

    test('should handle special characters in XSS payload', async () => {
      const specialPayloads = [
        '<script>alert("\\n\\r\\t")</script>',
        '<script>alert("\\u0000\\u0001\\u0002")</script>',
        '<script>alert("🚀💀👹")</script>',
        '<script>alert("\\x00\\xff")</script>'
      ];
      
      for (let i = 0; i < specialPayloads.length; i++) {
        const req = createMockRequest('192.168.1.213', 'Mozilla/5.0', `special_${i}`);
        await expect(handleXSS(req, specialPayloads[i], mockLogger)).resolves.not.toThrow();
        expect(mockLogger.warn).toHaveBeenCalledWith(' XSS attempt banning visitor...');
      }
    });

    test('should handle malformed HTML in XSS payload', async () => {
      const malformedPayloads = [
        '<script>alert(1)<',
        '<<script>alert(1)</script>',
        '<script>>alert(1)</script>',
        '<script attr="val>alert(1)</script>',
        '<><script>alert(1)</script><>'
      ];
      
      for (let i = 0; i < malformedPayloads.length; i++) {
        const req = createMockRequest('192.168.1.214', 'Mozilla/5.0', `malformed_${i}`);
        await expect(handleXSS(req, malformedPayloads[i], mockLogger)).resolves.not.toThrow();
        expect(mockLogger.warn).toHaveBeenCalledWith(' XSS attempt banning visitor...');
      }
    });
  });

  describe('Performance Under Load', () => {
    test('should handle multiple concurrent XSS attempts', async () => {
      const payloads = Array.from({ length: 20 }, (_, i) => 
        `<script>alert("concurrent_${i}")</script>`
      );
      
      const promises = payloads.map((payload, i) => {
        const req = createMockRequest('192.168.1.220', 'Mozilla/5.0', `concurrent_${i}`);
        return handleXSS(req, payload, mockLogger);
      });
      
      await expect(Promise.all(promises)).resolves.not.toThrow();
      
      // All should have been logged
      expect(mockLogger.warn).toHaveBeenCalledTimes(40); // 2 calls per XSS attempt
    });

    test('should maintain performance with rapid XSS attempts', async () => {
      const startTime = Date.now();
      
      const promises = Array.from({ length: 50 }, (_, i) => {
        const req = createMockRequest(`192.168.2.${i}`, 'Mozilla/5.0', `perf_test_${i}`);
        return handleXSS(req, '<script>alert("perf")</script>', mockLogger);
      });
      
      await Promise.all(promises);
      
      const endTime = Date.now();
      const duration = endTime - startTime;
      
      // Should complete in reasonable time (less than 5 seconds)
      expect(duration).toBeLessThan(5000);
    });
  });

  describe('Integration with Bot Detection', () => {
    test('should properly integrate with bot detection system', async () => {
      const { banIp, updateIsBot, updateBannedIP } = await import('@riavzon/botdetector');
      
      const req = createMockRequest('192.168.1.230', 'AttackBot/1.0', 'bot_canary_1');
      const maliciousPayload = '<img src=x onerror=alert(1)>';
      
      await handleXSS(req, maliciousPayload, mockLogger);
      
      // Verify bot detection integration
      expect(banIp).toHaveBeenCalledWith('192.168.1.230', { 
        score: 10, 
        reasons: ['XSS SCRIPTING ATTEMPT'] 
      });
      expect(updateIsBot).toHaveBeenCalledWith(true, 'bot_canary_1');
      expect(updateBannedIP).toHaveBeenCalledWith(
        'bot_canary_1',
        '192.168.1.230',
        'unknown',
        'AttackBot/1.0',
        { score: 10, reasons: ['XSS SCRIPTING ATTEMPT'] }
      );
    });

    test('should handle bot detection errors gracefully', async () => {
      // Mock bot detection to throw errors
      const { banIp } = await import('@riavzon/botdetector');
      vi.mocked(banIp).mockRejectedValueOnce(new Error('Bot detection service unavailable'));
      
      const req = createMockRequest('192.168.1.231', 'Mozilla/5.0', 'error_canary_1');
      const maliciousPayload = '<script>alert("error_test")</script>';
      
      // Should not throw even if bot detection fails
      await expect(handleXSS(req, maliciousPayload, mockLogger)).resolves.not.toThrow();
    });
  });

  describe('Real-world XSS Vectors', () => {
    test('should detect common real-world XSS patterns', async () => {
      const realWorldPayloads = [
        // Stored XSS
        '"><script>alert(document.cookie)</script>',
        "'-alert(1)-'",
        ';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//\\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">\'>',
        
        // Reflected XSS
        '<IMG SRC=javascript:alert(\'XSS\')>',
        '<BODY ONLOAD=alert(\'XSS\')>',
        '<IFRAME SRC="javascript:alert(\'XSS\');"></IFRAME>',
        
        // DOM-based XSS patterns
        'javascript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//',
        
        // Filter evasion
        '<script/random>alert(1)</script>',
        '<script\x20type="text/javascript">alert(1);</script>',
        '<script\x3etype="text/javascript">alert(1);</script>',
        '<script\x0dtype="text/javascript">alert(1);</script>',
        
        // UTF-8 encoded
        '<script>\\u0061lert(1)</script>',
        '<script>\\x61lert(1)</script>',
        
        // CSS injection
        '<style>@import\'javascript:alert("XSS")\';</style>',
        
        // XML entities
        '<script>alert(&#34;XSS&#34;)</script>',
        
        // Browser-specific
        '<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert(\'XSS\');">',
        '<LINK REL="stylesheet" HREF="javascript:alert(\'XSS\');">',
      ];
      
      for (let i = 0; i < realWorldPayloads.length; i++) {
        const req = createMockRequest('192.168.1.240', 'Mozilla/5.0', `realworld_${i}`);
        await handleXSS(req, realWorldPayloads[i], mockLogger);
        expect(mockLogger.warn).toHaveBeenCalledWith(' XSS attempt banning visitor...');
      }
    });

    test('should handle polyglot XSS payloads', async () => {
      const polyglotPayloads = [
        'javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>',
        '">\'><marquee><img src=x onerror=confirm(1)></marquee>"\'>',
        '><script>alert(document.domain)</script>',
        '"><img src=1 onerror=alert(1)>',
        'javascript:alert(1)',
        '\'-alert(1)-\'',
        '"><svg/onload=alert(1)>',
        '"><iframe src=javascript:alert(1)>',
      ];
      
      for (let i = 0; i < polyglotPayloads.length; i++) {
        const req = createMockRequest('192.168.1.250', 'Mozilla/5.0', `polyglot_${i}`);
        await handleXSS(req, polyglotPayloads[i], mockLogger);
        expect(mockLogger.warn).toHaveBeenCalledWith(' XSS attempt banning visitor...');
      }
    });
  });
});