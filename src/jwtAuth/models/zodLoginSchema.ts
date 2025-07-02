import { makeSafeString } from "../utils/zodSafeStringMaker.js";
import { z } from "zod/v4";

export const login = z.object({ 

email: makeSafeString({
        min: 10,
        max: 80,
        pattern: /^(?!\.)(?!.*\.\.)[A-Za-z0-9_'-.]+[A-Za-z0-9_-]@[A-Za-z][A-Za-z-]*(?:\.[A-Za-z]{1,4}){1,3}$/,
        patternMsg: `Invalid email`
}),

password: 
    z.string()
    .min(12)
    .max(64)
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d])\S{12,64}$/,
    `Invalid password`
    ),
}).required();
 export type Login = z.infer<typeof login>;