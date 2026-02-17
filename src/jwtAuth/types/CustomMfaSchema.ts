import * as z from 'zod';
import { makeSafeString } from '../utils/zodSafeStringMaker.js';

/**
 * Zod schemas for Custom MFA flow validation.
 */

/**
 * Schema for initializing a custom MFA flow.
 * 
 * @property {string} random - A high-entropy random string. 
 *   Length must be between 254 and 500 characters to ensure security.
 * @property {string} reason - The purpose of the MFA flow (e.g., 'login', 'withdraw').
 *   Length must be between 0 and 100 characters.
 */
export const schema = z.object({
    random: makeSafeString({
        min: 254,
        max: 500,
        patternMsg: "Invalid random"
    }),
    reason: makeSafeString({
        min: 0,
        max: 100
    }),
}).required()

/**
 * Schema for verifying a custom MFA magic link.
 * 
 * @description
 * This schema extends the base flow schema with additional fields 
 * required for the magic link verification process.
 * 
 * @property {string} random - The original random string.
 * @property {string} reason - The original reason.
 * @property {number} visitor - The visitor ID (coerced).
 * @property {string} token - The magic link JWT token.
 */
export const verificationLink = z.object({
    ...schema.shape,
    visitor: z.coerce.number(),
    token: z.string()
})
export type VerificationLinkSchema = z.infer<typeof verificationLink>
export type Schema = z.infer<typeof schema>