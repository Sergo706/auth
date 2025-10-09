
export function deriveLastNames (fullName?: string,given?: string, family?: string, explicitLast?: string): string {
const stripEnds = (s: string) => s
          .replace(/^[\s,\-–—]+/, '')
          .replace(/^[\[({\"'“‘`]+/, '')
          .replace(/[\])}\"'”’`]+$/, '')
          .trim();

        if (family && family.trim()) return stripEnds(family);
        if (explicitLast && explicitLast.trim()) return stripEnds(explicitLast);

        const full = (fullName ?? '').trim();
        const givenTrim = (given ?? '').trim();
        if (!full) return 'No lastname';

        let remainder = '';
        if (givenTrim && full.toLowerCase().startsWith(givenTrim.toLowerCase())) {
            remainder = full.slice(givenTrim.length).trim();
        } else {
            const parts = full.replace(/\s{2,}/g, ' ').split(/\s+/).filter(Boolean);
            remainder = parts.length > 1 ? parts.slice(1).join(' ') : '';
        }

        remainder = stripEnds(remainder);
        return remainder || 'No lastname';
    };