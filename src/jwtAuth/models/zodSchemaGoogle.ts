import { z } from "zod/v4"; 
import { makeSafeString } from "../utils/zodSafeStringMaker.js";

export const googleAuth = z.object({ 
iss: z.union([
      z.literal("https://accounts.google.com"),
      z.literal("accounts.google.com"),
    ]),
azp: z.literal("837342425464-8uc9bcgb1q1fliapbih2r2cgdkvrdua1.apps.googleusercontent.com"),
aud: z.literal("837342425464-8uc9bcgb1q1fliapbih2r2cgdkvrdua1.apps.googleusercontent.com"),
sub: z.string().regex(/^[0-9]+$/, "Invalid subject ID"),
email: makeSafeString({
        min: 10,
        max: 80,
        pattern: /^(?!\.)(?!.*\.\.)[A-Za-z0-9_'-.]+[A-Za-z0-9_-]@[A-Za-z][A-Za-z-]*(?:\.[A-Za-z]{1,4}){1,3}$/,
        patternMsg: `Please Enter a valid email`
}),
email_verified: z.boolean(),
name: makeSafeString({ min: 2, max: 72 }),
given_name: makeSafeString({ min: 2, max: 72 }),
picture: makeSafeString({ min: 2, max: 250 }),
family_name: makeSafeString({ min: 2, max: 72 }).optional(),
locale: makeSafeString({ min: 2, max: 20 }).optional(),
})

export const customProviders = {

}
 export type NewUserGoogle = z.infer<typeof googleAuth>;