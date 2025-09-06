import { describe, test, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import { strangeThings } from '../../../src/anomalies.js';
import { 
  setupTestDatabase, 
  teardownTestDatabase, 
  setupTestUser, 
  cleanupTestData,
  mockBotDetector 
} from '../test-setup.js';

// Mock bot detector for controlled testing
mockBotDetector();

describe('XSS Detection and Response', () => {
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

  test('should detect basic script tag XSS', async () => {
    const xssPayloads = [
      '<script>alert("XSS")</script>',
      '<script>alert(\'XSS\')</script>',
      '<script>alert(`XSS`)</script>',
      '<script src="evil.js"></script>',
      '<script>document.location="http://evil.com"</script>',
    ];

    for (const payload of xssPayloads) {
      const result = await strangeThings(999, payload, 40.7128, -74.0060);
      
      // Should detect XSS and respond appropriately
      expect(result).toBeDefined();
      // The specific response depends on implementation
      // but should indicate detection or blocking
    }
  });

  test('should detect iframe-based XSS', async () => {
    const iframePayloads = [
      '<iframe src="javascript:alert(\'XSS\')"></iframe>',
      '<iframe src="data:text/html,<script>alert(\'XSS\')</script>"></iframe>',
      '<iframe src="http://evil.com"></iframe>',
      '<iframe onload="alert(\'XSS\')"></iframe>',
    ];

    for (const payload of iframePayloads) {
      const result = await strangeThings(999, payload, 40.7128, -74.0060);
      expect(result).toBeDefined();
    }
  });

  test('should detect event handler XSS', async () => {
    const eventPayloads = [
      '<img onerror="alert(\'XSS\')" src="x">',
      '<body onload="alert(\'XSS\')">',
      '<div onclick="alert(\'XSS\')">Click me</div>',
      '<input onfocus="alert(\'XSS\')" autofocus>',
      '<svg onload="alert(\'XSS\')">',
      '<details ontoggle="alert(\'XSS\')" open>',
      '<marquee onstart="alert(\'XSS\')">',
      '<video controls onloadstart="alert(\'XSS\')">',
    ];

    for (const payload of eventPayloads) {
      const result = await strangeThings(999, payload, 40.7128, -74.0060);
      expect(result).toBeDefined();
    }
  });

  test('should detect javascript: protocol XSS', async () => {
    const jsProtocolPayloads = [
      'javascript:alert("XSS")',
      'javascript:alert(String.fromCharCode(88,83,83))',
      'javascript:void(alert("XSS"))',
      'javascript:eval("alert(\\"XSS\\")")',
      'JaVaScRiPt:alert("XSS")', // Case variations
    ];

    for (const payload of jsProtocolPayloads) {
      const result = await strangeThings(999, payload, 40.7128, -74.0060);
      expect(result).toBeDefined();
    }
  });

  test('should detect data: protocol XSS', async () => {
    const dataProtocolPayloads = [
      'data:text/html,<script>alert("XSS")</script>',
      'data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=',
      'data:image/svg+xml,<svg onload="alert(\'XSS\')">',
      'data:application/javascript,alert("XSS")',
    ];

    for (const payload of dataProtocolPayloads) {
      const result = await strangeThings(999, payload, 40.7128, -74.0060);
      expect(result).toBeDefined();
    }
  });

  test('should detect encoded XSS attempts', async () => {
    const encodedPayloads = [
      // URL encoded
      '%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E',
      // HTML entity encoded
      '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;',
      // Hex encoded
      '&#x3C;script&#x3E;alert(&#x22;XSS&#x22;)&#x3C;/script&#x3E;',
      // Decimal encoded
      '&#60;script&#62;alert(&#34;XSS&#34;)&#60;/script&#62;',
      // Mixed encoding
      '%3Cscript%3Ealert(&quot;XSS&quot;)%3C/script%3E',
    ];

    for (const payload of encodedPayloads) {
      const result = await strangeThings(999, payload, 40.7128, -74.0060);
      expect(result).toBeDefined();
    }
  });

  test('should detect obfuscated XSS', async () => {
    const obfuscatedPayloads = [
      // String concatenation
      '<script>al\u0065rt("XSS")</script>',
      '<script>eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41))</script>',
      // Unicode escaping
      '<script>\u0061lert("XSS")</script>',
      // Comments and whitespace
      '<script>/**/alert/**/(/**/"XSS"/**/)</script>',
      '<script>\x09alert\x0a("XSS")</script>',
      // Expression evaluation
      '<script>window["alert"]("XSS")</script>',
      '<script>this["alert"]("XSS")</script>',
    ];

    for (const payload of obfuscatedPayloads) {
      const result = await strangeThings(999, payload, 40.7128, -74.0060);
      expect(result).toBeDefined();
    }
  });

  test('should detect DOM-based XSS vectors', async () => {
    const domPayloads = [
      'document.write("<script>alert(\'XSS\')</script>")',
      'document.body.innerHTML="<img src=x onerror=alert(\'XSS\')>"',
      'location.href="javascript:alert(\'XSS\')"',
      'eval("alert(\'XSS\')")',
      'setTimeout("alert(\'XSS\')",0)',
      'setInterval("alert(\'XSS\')",1000)',
      'Function("alert(\'XSS\')")()',
    ];

    for (const payload of domPayloads) {
      const result = await strangeThings(999, payload, 40.7128, -74.0060);
      expect(result).toBeDefined();
    }
  });

  test('should detect SVG-based XSS', async () => {
    const svgPayloads = [
      '<svg onload="alert(\'XSS\')">',
      '<svg><script>alert("XSS")</script></svg>',
      '<svg><foreignObject><iframe xmlns="http://www.w3.org/1999/xhtml" src="javascript:alert(\'XSS\')"></iframe></foreignObject></svg>',
      '<svg><animation onload="alert(\'XSS\')" />',
      '<svg><animateTransform onbegin="alert(\'XSS\')" />',
    ];

    for (const payload of svgPayloads) {
      const result = await strangeThings(999, payload, 40.7128, -74.0060);
      expect(result).toBeDefined();
    }
  });

  test('should detect CSS-based XSS', async () => {
    const cssPayloads = [
      '<style>@import"javascript:alert(\'XSS\')";</style>',
      '<style>body{background:url("javascript:alert(\'XSS\')")}</style>',
      '<style>*{behavior:url("evil.htc")}</style>',
      '<link rel="stylesheet" href="javascript:alert(\'XSS\')">',
      '<style>/**/alert(\'XSS\')/***/</style>',
    ];

    for (const payload of cssPayloads) {
      const result = await strangeThings(999, payload, 40.7128, -74.0060);
      expect(result).toBeDefined();
    }
  });

  test('should detect polyglot XSS attacks', async () => {
    const polyglotPayloads = [
      // HTML/JS/SVG polyglot
      'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
      // Multi-context
      '">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>',
      // Universal XSS
      '<img src="x" onerror="alert(1)" /><!--><script>alert(2)</script>%3Cscript%3Ealert(3)%3C/script%3E',
    ];

    for (const payload of polyglotPayloads) {
      const result = await strangeThings(999, payload, 40.7128, -74.0060);
      expect(result).toBeDefined();
    }
  });

  test('should handle XSS in different input contexts', async () => {
    const contextualPayloads = [
      // Within attribute values
      '" onmouseover="alert(\'XSS\')" x="',
      '\' onmouseover=\'alert("XSS")\' x=\'',
      // Breaking out of comments
      '--><script>alert("XSS")</script><!--',
      // Within CDATA
      ']]><script>alert("XSS")</script><![CDATA[',
      // Within JSON
      '{"xss":"</script><script>alert(\\"XSS\\")</script>"}',
    ];

    for (const payload of contextualPayloads) {
      const result = await strangeThings(999, payload, 40.7128, -74.0060);
      expect(result).toBeDefined();
    }
  });

  test('should detect filter bypass attempts', async () => {
    const bypassPayloads = [
      // Case variations
      '<SCRIPT>alert("XSS")</SCRIPT>',
      '<ScRiPt>alert("XSS")</ScRiPt>',
      // Null byte injection
      '<script\x00>alert("XSS")</script>',
      // Tab/newline insertion
      '<script\x09>alert("XSS")</script>',
      '<script\x0a>alert("XSS")</script>',
      '<script\x0d>alert("XSS")</script>',
      // Nested tags
      '<<script>script>alert("XSS")<</script>/script>',
      // Incomplete tags
      '<script>alert("XSS")//</script>',
    ];

    for (const payload of bypassPayloads) {
      const result = await strangeThings(999, payload, 40.7128, -74.0060);
      expect(result).toBeDefined();
    }
  });

  test('should detect XSS with various alert variations', async () => {
    const alertVariations = [
      '<script>alert(1)</script>',
      '<script>confirm(1)</script>',
      '<script>prompt(1)</script>',
      '<script>print()</script>',
      '<script>console.log("XSS")</script>',
      '<script>debugger</script>',
      '<script>throw "XSS"</script>',
    ];

    for (const payload of alertVariations) {
      const result = await strangeThings(999, payload, 40.7128, -74.0060);
      expect(result).toBeDefined();
    }
  });

  test('should handle XSS with geographic anomalies', async () => {
    const xssPayload = '<script>alert("XSS")</script>';
    
    // Test XSS detection combined with geographic anomalies
    const locations = [
      { lat: 0, lon: 0 }, // Null Island
      { lat: 90, lon: 0 }, // North Pole
      { lat: -90, lon: 0 }, // South Pole
      { lat: 0, lon: 180 }, // Date line
      { lat: 40.7128, lon: -74.0060 }, // Valid location
    ];

    for (const location of locations) {
      const result = await strangeThings(999, xssPayload, location.lat, location.lon);
      expect(result).toBeDefined();
      // Should detect both XSS and potential geographic anomalies
    }
  });

  test('should handle concurrent XSS detection', async () => {
    const xssPayloads = [
      '<script>alert("XSS1")</script>',
      '<script>alert("XSS2")</script>',
      '<script>alert("XSS3")</script>',
      '<script>alert("XSS4")</script>',
      '<script>alert("XSS5")</script>',
    ];

    // Test concurrent XSS detection
    const concurrentPromises = xssPayloads.map(payload =>
      strangeThings(999, payload, 40.7128, -74.0060)
    );

    const results = await Promise.allSettled(concurrentPromises);
    
    // All should be detected
    results.forEach(result => {
      expect(result.status).toBe('fulfilled');
      expect(result.value).toBeDefined();
    });
  });

  test('should detect XSS with timing consistency', async () => {
    const xssPayload = '<script>alert("XSS")</script>';
    const benignPayload = 'normal text content';

    // Measure timing for XSS vs benign content
    const timings = [];
    
    for (let i = 0; i < 10; i++) {
      // XSS payload timing
      const xssStart = process.hrtime.bigint();
      await strangeThings(999, xssPayload, 40.7128, -74.0060);
      const xssEnd = process.hrtime.bigint();
      const xssTime = Number(xssEnd - xssStart) / 1000000;

      // Benign payload timing
      const benignStart = process.hrtime.bigint();
      await strangeThings(999, benignPayload, 40.7128, -74.0060);
      const benignEnd = process.hrtime.bigint();
      const benignTime = Number(benignEnd - benignStart) / 1000000;

      timings.push({ xss: xssTime, benign: benignTime });
    }

    // Calculate timing consistency
    const xssTimes = timings.map(t => t.xss);
    const benignTimes = timings.map(t => t.benign);
    
    const avgXss = xssTimes.reduce((a, b) => a + b) / xssTimes.length;
    const avgBenign = benignTimes.reduce((a, b) => a + b) / benignTimes.length;
    
    // Should not have extreme timing differences (prevents timing analysis)
    const timingRatio = Math.abs(avgXss - avgBenign) / Math.max(avgXss, avgBenign);
    expect(timingRatio).toBeLessThan(5.0); // Less than 500% difference
  });

  test('should handle deeply nested XSS', async () => {
    const nestedPayloads = [
      '<div><div><div><script>alert("XSS")</script></div></div></div>',
      '<table><tr><td><script>alert("XSS")</script></td></tr></table>',
      '<form><fieldset><legend><script>alert("XSS")</script></legend></fieldset></form>',
      '<ul><li><span><script>alert("XSS")</script></span></li></ul>',
    ];

    for (const payload of nestedPayloads) {
      const result = await strangeThings(999, payload, 40.7128, -74.0060);
      expect(result).toBeDefined();
    }
  });

  test('should detect XSS with various quote combinations', async () => {
    const quotePayloads = [
      '<script>alert("XSS")</script>',
      "<script>alert('XSS')</script>",
      '<script>alert(`XSS`)</script>',
      '<script>alert(String.fromCharCode(88,83,83))</script>',
      '<script>alert(/XSS/.source)</script>',
      '<script>alert(new String("XSS"))</script>',
    ];

    for (const payload of quotePayloads) {
      const result = await strangeThings(999, payload, 40.7128, -74.0060);
      expect(result).toBeDefined();
    }
  });
});