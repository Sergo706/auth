import sanitizeHtml from 'sanitize-html';
import he from 'he'

interface html {
  htmlFound: boolean;
    tags?: {
      tagName: string;
      attributes?: Record<string, string>;
    } 
}

export default function sanitizeInputString(vall: string): {vall :string, results: html} {
  let results: html = { htmlFound: false };

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
        console.log('URI-decode success:', clean);
      } catch {
        console.log('URI-decode failed, carrying on with:', clean);
      }
      clean = he.decode(clean);
      
      console.log(prev, `runned ${i++} times. prev: ${prev}  Now: ${clean}`);
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
  console.log(`Final Results:  ${stripped}`)
  return { vall: stripped, results }
}