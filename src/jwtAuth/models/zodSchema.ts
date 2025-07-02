import { z } from "zod/v4"; 
import sanitizeInputString from "../utils/htmlSanitizer.js";

function makeSafeString(opt: {
  min: number,
  max: number
  pattern: RegExp
  patternMsg: string
}) {
return z
.string()
.min(opt.min, `Must be at least ${opt.min} characters`)
.max(opt.max, `Max of ${opt.max} characters are allowed`)
.regex(opt.pattern, opt.patternMsg)
.check((ctx) => {
    const { results } = sanitizeInputString(ctx.value)
    if (results.htmlFound) {
        ctx.issues.push({
            code: "custom",
            message: `HTML found in input\n TAGS: ${results.tags?.tagName} attributes: ${results.tags?.attributes}`,
            input: ctx.value
        })
    }

})
.transform((val) => sanitizeInputString(val).vall)
}

export const email = z.strictObject({ 
    email:makeSafeString({
        min: 10,
        max: 80,
        pattern: /^(?!\.)(?!.*\.\.)[A-Za-z0-9_'-.]+[A-Za-z0-9_-]@[A-Za-z][A-Za-z-]*(?:\.[A-Za-z]{1,4}){1,3}$/,
        patternMsg: `Please Enter a valid email`
    })
}).required();


export const passwords = z.strictObject({
password: 
    z.string()
    .min(12)
    .max(64)
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d])\S{12,64}$/,
    `Password must be at least 12 characters long, include atleast one uppercase letter, one lowercase letter, one digit, and one special character.`
    ),

    confirmedPassword:
    z.string()
    .min(12)
    .max(64)
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d])\S{12,64}$/,
    `Password must be at least 12 characters long, include atleast one uppercase letter, one lowercase letter, one digit, and one special character.`
    ),
}).required()
    .refine((data) => data.password === data.confirmedPassword, {
    message: "Passwords don't match",
    path: ["confirm"],
  })

export const code = z.strictObject({ 
    code:makeSafeString({
        min: 7,
        max: 7,
        pattern: /^\d{7}$/,
        patternMsg: `Invalid or expired code`
    })
}).required();
