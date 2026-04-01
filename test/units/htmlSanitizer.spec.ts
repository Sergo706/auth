import { describe, it, expect, afterEach } from 'vitest';
import sanitizeInputString from '~~/utils/htmlSanitizer.js';
import { newConfig } from '../test-utils/changeConfigs.js';
import { configuration } from '~~/config/configuration.js';
import { config } from '../configs/config.js';

describe('sanitizeInputString', () => {
    afterEach(async () => await configuration(config))

    it('should strip simple HTML tags', () => {
        const input = '<script>alert("xss")</script>Hello <b>World</b>';
        const { vall, results } = sanitizeInputString(input);
        
        expect(vall).toBe('Hello World');
        expect(results.htmlFound).toBe(true);
    });

    it('should decode URI encoding and sanitize', () => {
        const input = '%3Cscript%3Ealert(1)%3C/script%3E';
        const { vall, results } = sanitizeInputString(input);
        
        expect(vall).toBe('');
        expect(results.htmlFound).toBe(true);
    })

    it('should strip highly obfuscated XSS payloads', () => {
        const payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<a href="javascript:alert(1)">click</a>',
            '<iframe src="javascript:alert(1)"></iframe>',
            '<svg/onload=alert(1)>',
            '<p onmouseover="alert(\'xss\')">hover me</p>',
            '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;">link</a>',
        ];
        
        for (const input of payloads) {
            const { vall, results } = sanitizeInputString(input);
            expect(results.htmlFound).toBe(true);
            expect(vall).not.toContain('<script');
            expect(vall).not.toContain('onerror');
            expect(vall).not.toContain('javascript:');
        }
    });

    it('should handle complex deep encoding and URI malformation', () => {
        let deepInput = 'script';
        for (let i = 0; i < 5; i++) {
            deepInput = encodeURIComponent(deepInput);
        }
        const { vall, results } = sanitizeInputString(deepInput);
        expect(results.htmlFound).toBe(false);
        expect(vall).toBe('script');

        const mixedInput = '%3Cscript%3Ehello%E0%A4%A';
        const mixedResult = sanitizeInputString(mixedInput);
        expect(mixedResult.results.htmlFound).toBe(true);
        expect(mixedResult.results.tags?.tagName).toBe('Rejected: Malformed URI');
    });

    it('should enforce maxAllowedInputLength', () => {
        const max = 524288;
        const tooBig = 'a'.repeat(max + 1);
        
        expect(() => sanitizeInputString(tooBig)).toThrow(/Input too large/);
    });

    it('should provide comprehensive sanitization for special characters', () => {
        const input = 'Check out: < > & " \' ` $ { } [ ]';
        const { vall } = sanitizeInputString(input);
        
        expect(vall).toBe('Check out: &amp;lt; &amp;gt; &amp;amp; &quot; &#x27; &#x60; $ { } [ ]');
    });

    it('should handle advanced NFKC normalization and accents', () => {
        const inputs = [
            { raw: 'Ｈｅｌｌｏ', expected: 'Hello' },
            { raw: '¼', expected: '1⁄4' },
            { raw: 'ℌ', expected: 'H' },
            { raw: 'Café', expected: 'Café' },
        ];
        
        for (const { raw, expected } of inputs) {
            const { vall } = sanitizeInputString(raw);
            expect(vall).toBe(expected);
        }
    });

    it('should detect HTML even if buried in other text', () => {
        const input = 'This is a normal sentence. <img src="x" onerror="alert(1)"> And it continues.';
        const { results } = sanitizeInputString(input);
        expect(results.htmlFound).toBe(true);
        expect(results.tags?.tagName).toBe('lenght is !== after a clean.');
    });
    

    it('should allow valid algebra without false positives', () => {
        const input = 'Use the logic: if (a < b)';
        const { vall, results } = sanitizeInputString(input);
        
        expect(results.htmlFound).toBe(false); 
        expect(vall).toBe("Use the logic: if (a &amp;lt; b)");
    });

    it('should survive recursive expansion attack', async () => {
        
        const temp = newConfig({
           htmlSanitizer: {
            maxAllowedInputLength: 500000,
            IrritationCount: 5 
           }
        })
        
        await configuration(temp)

        let attack = '%'; 
        for (let i = 0; i < 50; i++) {
            attack = encodeURIComponent(attack);
        }
        
        const start = performance.now();
        const {vall, results } = sanitizeInputString(attack);
        const end = performance.now();

        expect(results.htmlFound).toBe(true); 
        expect(results.tags?.tagName).toContain('Excessive Encoding');
        expect(end - start).toBeLessThan(100);
        expect(vall).toBe("");
    });

    it('should catch the full width script tag bypass', () => {
        const input = '\uFF1Cscript\uFF1Ealert(1)\uFF1C/script\uFF1E';
        const { vall, results } = sanitizeInputString(input);

        expect(results.htmlFound).toBe(true);
        expect(vall).not.toContain('script');
        expect(vall).toBe("");
    });

    it('should handle attributes containing greater-than signs', () => {
        const input = '<div title=">">Secret Content</div>'; 
        const { vall } = sanitizeInputString(input);

        expect(vall).toBe('Secret Content');
        expect(vall).not.toContain('">'); 
    });
});


describe('sanitizeInputString stress and nesting tests', () => {

    it('should handle deep nesting', () => {
        const depth = 500;
        const input = '<div>'.repeat(depth) + 'Content' + '</div>'.repeat(depth);
        
        const start = performance.now();
        const { vall, results } = sanitizeInputString(input);
        const end = performance.now();

        expect(vall).toBe('Content');
        expect(results.htmlFound).toBe(true);
        expect(end - start).toBeLessThan(30); 
    });

    it('should not block the event loop and detect nested inputs', async () => {
        const depth = 500;
        const input = '<div>'.repeat(depth) + 
        `<svg>
                <foreignObject>
                    <body xmlns="http://www.w3.org/1999/xhtml">
                        <script>alert(1)</script>
                    </body>
                </foreignObject>
            </svg>`.repeat(depth) + 
        '</div>'.repeat(depth);

      const temp = newConfig({
            htmlSanitizer: {
             maxAllowedInputLength: 500000,
             IrritationCount: 500 
            }
        })

        await configuration(temp)
        const start = performance.now();
        const { vall, results } = sanitizeInputString(input);
        const end = performance.now();

        expect(results.htmlFound).toBe(true);
        expect(vall).not.toContain('<script');
        expect(vall).toBe("");
        expect(end - start).toBeGreaterThan(0);
        expect(end - start).toBeLessThan(60);

        const heavyInput = '%26lt%3Bscript%26gt%3Balert(1)%26lt%3B%2Fscript%26gt%3B'.repeat(1000);
        const secondPhase = performance.now();
        const { vall: secondPhaseValues, results: secondPhaseResults } = sanitizeInputString(heavyInput);
        const secondEnd = performance.now();
        expect(secondPhaseResults.htmlFound).toBe(true);
        expect(secondPhaseValues).toBe('');
        expect(secondEnd - secondPhase).toBeGreaterThan(0);
        expect(secondEnd - secondPhase).toBeLessThan(30);
});


    it('should handle russian dolls', () => {
        const nestedPolyglot = '%26lt%3Bscript%26gt%3Balert(1)%26lt%3B%2Fscript%26gt%3B';
        
        const { vall, results } = sanitizeInputString(nestedPolyglot);
        
        expect(results.htmlFound).toBe(true);
        expect(vall).not.toContain('<script');
        expect(vall).not.toContain('alert(1)');
        expect(vall).toBe('');

    });

    it('should handle ghost character nesting', () => {
        const ghosts = [
            '<\u0000script>alert(1)</script>',
            '<scr\u00ADipt>alert(1)</script>',
            '<s\tcript>alert(1)</script>', 
        ];

        for (const input of ghosts) {
            const { results, vall } = sanitizeInputString(input);
            expect(vall).not.toContain('<script>');
            expect(vall).toBe("");
        }
    });

    it('should handle SVG/XML namespace nesting', () => {
        const input = `
            <svg>
                <foreignObject>
                    <body xmlns="http://www.w3.org/1999/xhtml">
                        <script>alert(1)</script>
                    </body>
                </foreignObject>
            </svg>
        `;
        const { vall, results } = sanitizeInputString(input);
        
        expect(results.htmlFound).toBe(true);
        expect(vall).not.toContain('<script');
        expect(vall).toBe('');
    });

    it('should handle comment obfuscation nesting', () => {
        const input = '-->';
        const { vall, results } = sanitizeInputString(input);

        expect(vall).not.toContain('<script');
        expect(vall).toBe('--&amp;gt;');
    });

    it('should handle unclosed tag flooding', () => {
        const input = '<div '.repeat(100) + '><script>alert(1)</script>';
        
        const { vall, results } = sanitizeInputString(input);
        
        expect(results.htmlFound).toBe(true);
        expect(vall).not.toContain('<script');
        expect(vall).toBe('');
    });

    it('should handle protocol nesting in attributes', () => {
        const inputs = [
            '<a href="j&Tab;a&Tab;v&Tab;a&Tab;s&Tab;c&Tab;r&Tab;i&Tab;p&Tab;t&Tab;:alert(1)">Click</a>',
            '<a href="jav&#x09;ascript:alert(1)">Click</a>',
            '<a href="javascript:javascript:alert(1)">Click</a>'
        ];

        for (const input of inputs) {
            const { vall } = sanitizeInputString(input);
            expect(vall).not.toContain('javascript:');
            expect(vall).not.toContain('alert(1)');
            expect(vall).toBe('Click');
        }
    });

    it('should handle unicode normalization collisions', () => {

        const input = '<\u212Aeyframe onstart=alert(1)>'; 
        const { vall, results } = sanitizeInputString(input);

        expect(results.htmlFound).toBe(true);
        expect(vall).not.toContain('<keyframe');
        expect(vall).not.toContain('onstart');
        expect(vall).toBe('');
    });
});