import { z } from "zod/v4"; 
import sanitizeInputString from "./htmlSanitizer.js";


/**
 * @description
 * Make a safe Zod string that will be sanitized.
 *
 * @param {Object} opt - Configuration options.
 * @param {number} opt.min - Minimum string length.
 * @param {number} opt.max - Maximum string length.
 * @param {RegExp} [opt.pattern] - Regular expression the string must match.
 * @param {string} [opt.patternMsg] - Error message if the pattern does not match.
 *
 * @returns {string}
 *   A Zod string schema configured to enforce length and pattern rules.
 *
 * @see {@link ./zodSafeStringMaker.js}
 *
 * @example
 * import { z } from 'zod';
 * import { makeSafeString } from './zodSafeStringMaker';
 *
 * export const emailSchema = z.strictObject({
 *   email: makeSafeString({
 *     min: 10,
 *     max: 80,
 *     pattern: /^(?!\.)(?!.*\.\.)[A-Za-z0-9_'-.]+@[A-Za-z][A-Za-z-]*(?:\.[A-Za-z]{1,4}){1,3}$/,
 *     patternMsg: 'Please enter a valid email'
 *   })
 * }).required();
 */
export function makeSafeString(opt: {
  min: number,
  max: number
  pattern?: RegExp
  patternMsg?: string
}) {
let schema = z
    .string()
    .min(opt.min, `Must be at least ${opt.min} characters`)
    .max(opt.max, `Max of ${opt.max} characters are allowed`);
if (opt.pattern) {
    schema = schema.regex(opt.pattern, opt.patternMsg);
  }
  schema.check((ctx) => {
    const { results } = sanitizeInputString(ctx.value)
    if (results.htmlFound) {
        ctx.issues.push({
            code: "custom",
            message: `HTML found in input\n TAGS: ${results.tags?.tagName} attributes: ${results.tags?.attributes}`,
            input: ctx.value
        })
    }

}).transform((val) => sanitizeInputString(val).vall);
return schema;
}