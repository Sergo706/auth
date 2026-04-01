import * as z from 'zod';
import { makeSafeString } from '../utils/zodSafeStringMaker.js';

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

export const buildInMfaFlows = z.object({
    ...schema.shape,
    visitor: z.coerce.string(),
    token: z.string()
})

export type BuildInMfaFlowsSchema = z.infer<typeof buildInMfaFlows>