import { z } from "zod/v4"; 
import sanitizeInputString from "./htmlSanitizer.js";

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