import z from 'zod'
import crypto from 'node:crypto'

const zodFuncEnsureSha256 = z.function({
    input: [z.hash("sha256", {enc: 'hex'})],
    output: z.hash("sha256", {enc: 'hex'})
})
const sha256 = z.hash("sha256", {enc: 'hex'});

const zodFuncShouldDigest = z.function({
    input: [z.union([z.string(), z.hash("sha256", {enc: 'hex'})])],
    output: z.discriminatedUnion("wasHashed", [
        z.object({
            input: z.string(),
            wasHashed: z.literal(true)
        }), 
        z.object({
            input: z.hash("sha256", {enc: 'hex'}),
            wasHashed: z.literal(false)
        })
    ])
})

/**
 * Ensure a value is a SHA‑256 hex string (64 hex chars).
 *
 * Validates format and returns the same value if valid; otherwise throws.
 * Useful to assert that an input is already a digest in hex form.
 *
 * @param {string} input - Candidate string to validate as sha256 hex.
 * @returns {string} The unchanged input, typed as sha256 hex.
 * @throws {Error} When the string is not a 64‑char hex digest.
 */
export const ensureSha256Hex = zodFuncEnsureSha256.implement((input) => { 
    if (!/^[a-f0-9]{64}$/i.test(input)) {
        throw new Error('Malformed hashed token');
    }
    return input;
})


/**
 * Coerce a string into a SHA‑256 hex digest while preserving awareness of whether
 * the input was already hashed.
 *
 * If `input` is already a sha256 hex string, returns it unchanged with
 * `wasHashed: true`. Otherwise computes `sha256(input)` in hex and returns it
 * with `wasHashed: false`.
 *
 * @param {string} input - Either a raw string or a sha256 hex digest.
 * @returns {Promise<{ input: string; wasHashed: boolean }>} The hex digest and
 * a flag indicating whether hashing occurred.
 */
export const toDigestHex = zodFuncShouldDigest.implementAsync(async (input) => {
    try {
    const isHash = sha256.safeParse(input)
    if (isHash.success) {
       return {
         input,
         wasHashed: true
       };
    }
    const hashedValue = crypto.createHash('sha256').update(input).digest('hex');
        return {
            input: hashedValue,
            wasHashed: false
        }
} catch(err) {
    throw err;
 }
})
