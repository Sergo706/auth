import sanitizeHtml from 'sanitize-html';
import he from 'he'
import { getLogger } from './logger.js';
interface html {
  htmlFound: boolean;
    tags?: {
      tagName: string;
      attributes?: Record<string, string>;
    } 
}

/**
 * @description
 * Decode URI-encoded characters to Unicode (NFKC) and sanitize arbitrary HTML from the input string.
 *
 * @param {string} vall
 *   The raw HTML string to decode and sanitize.
 *
 * @returns {{
 *   vall: string;
 *   results: {
 *     htmlFound: boolean;
 *     tags: Array<{ tagName: string }>;
 *   };
 * }}
 *   An object containing:
 *   - `vall`: the decoded and cleaned string  
 *   - `results.htmlFound`: whether any HTML was detected  
 *   - `results.tags`: a list of detected tags, each with its `tagName`
 *
 * @see {@link ./htmlSanitizer.js}
 *
 * @example
 * const { vall, results } = sanitizeInputString(userSubmittedInput);
 * console.log(vall);           // sanitized text
 * console.log(results.tags);   // e.g. [{ tagName: 'div' }, { tagName: 'script' }]
 */
export default function sanitizeInputString(vall: string): {vall :string, results: html} {
  let results: html = { htmlFound: false };
  const log = getLogger().child({service: 'auth', branch: 'utils', type: 'sanitizeInputString'})
  let clean = vall
  .normalize('NFKC') 
  .replace(/[\uFEFF\u200B-\u200D\u202A-\u202E\uFF1C\uFF1E]/g, '')
  .replace(/[\uFF01-\uFF5E]/g, ch =>
    String.fromCharCode(ch.charCodeAt(0) - 0xFEE0)
  );

  try {
    clean = decodeURIComponent(clean);
  } catch {
    clean = clean.replace(/%[0-9A-Fa-f]{2}/g, seq => {
      try { 
        return decodeURIComponent(seq) 
      } catch {
         return seq 
        }
    });
  }
  

    let i = 1;
    while (true) {
    let prev = clean;
      try {
        clean = decodeURIComponent(clean);
        log.info({clean}, 'URI-decode success');
      } catch {
        log.info({clean},'URI-decode failed, carrying on' );
      }
      clean = he.decode(clean);
      
      log.info({prev}, `runned ${i++} times. prev: ${prev}  Now: ${clean}`);
      if (clean === prev) break;
    }
    
    const tagRx = /<\s*\/?\s*[A-Za-z][A-Za-z0-9-]*(?:\s+[^>]*?)?\s*>/i;
    if (
       tagRx.test(clean)    ||   
       /on\w+\s*=/i.test(clean)        ||   
       /javascript\s*:/i.test(clean)      
     ) {
       results.htmlFound = true;
     }

  const before = clean.length;
 clean = sanitizeHtml(clean, {
    allowedTags: [],
    allowedAttributes: {},
    allowedIframeHostnames: [],
    allowedSchemes: [],
    nestingLimit: 10,
    allowProtocolRelative: false,
    disallowedTagsMode: 'discard',
    textFilter(text) {
      if (tagRx.test(text)) results.htmlFound = true;
      return text;
    },
    onOpenTag: (tags, attr) => {
      results = {
        htmlFound: true,
        tags: {
          tagName: tags,
          attributes: attr,
        }
      };
    },
  })
  if (clean.length < before) {
    results = {
      htmlFound: true,
      tags: {
        tagName: `lenght is !== after a clean.`,  
      }
    };  
  }

  const stripped = clean
      .replace(/<[^>]*>/g, '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;') 
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/`/g,'&#x60;')
      .replace(/\$\{/g, '\\${')
      .trim();
  log.info({stripped}, `Final Results`)
  return { vall: stripped, results }
}