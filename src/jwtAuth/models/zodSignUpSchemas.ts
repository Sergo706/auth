import { z } from "zod/v4"; 
import { makeSafeString } from "../utils/zodSafeStringMaker.js";

export const newUser = z.strictObject({ 
    name: makeSafeString({
        min: 2,
        max: 72,
        pattern: /^[A-Za-z]+(?:(?:,\s*|\s+)[A-Za-z]+){0,3}$/,
        patternMsg:`Please enter 1 to 4 names (letters only), separated by commas or spaces. For example: 
        John
    
        John Doe
    
        John, Doe Something
    
        John, Doe, Something, Else”
     `
      })
    .transform(s => s.toLowerCase()),

    email:makeSafeString({
        min: 10,
        max: 80,
        pattern: /^(?!\.)(?!.*\.\.)[A-Za-z0-9_'-.]+[A-Za-z0-9_-]@[A-Za-z][A-Za-z-]*(?:\.[A-Za-z]{1,4}){1,3}$/,
        patternMsg: `Please enter a valid email.\n 
            Username (before @):\n
            Letters, digits, _ ' - . are allowed \n
    
            Cannot start or end with a dot, nor have “..”\n
    
            Domain (after @): \n
    
            First label must start with a letter (letters & hyphens allowed)\n
    
            Followed by 1 to 3 dot-separated labels\n
    
            Each of those labels must be 1–4 letters\n
    
            Examples:\n\n
    
    
            john-lastname414@example.com\n
    
            john@example.com\n
    
            alice.smith@domain.co.uk\n
    
            o_connor@my-domain.io`
    })
    .transform(s => s.toLowerCase()),

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

    rememberUser: z.literal("on").optional()  
    .transform(val => val === "on")
    .default(false),

    termsConsent: z.literal("on", 
    'Please Read and agree to the Terms of Use and Privacy Policy.')
    .transform(val => val === "on")
    .default(false),


  }).required()
    .refine((data) => data.password === data.confirmedPassword, {
    message: "Passwords don't match",
    path: ["confirm"],
  })

 export type NewUser = z.infer<typeof newUser>;