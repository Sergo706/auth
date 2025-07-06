import { ZodType, ZodSafeParseResult } from "zod/v4";
import { handleXSS } from "./handleXSS.js";
import { Request } from "express";
/**
 * @description
 * Validates raw input data against a Zod schema and logs any errors.
 *
 * @template T
 * @template Input
 *
 * @param {import('zod').ZodType<T, import('zod').ZodTypeDef, Input>} schema
 *   The Zod schema to validate against.
 * @param {Input} data
 *   The raw data to validate.
 * @param {import('express').Request} req
 *   The Express request object (for context/logging).
 * @param {import('pino').Logger} log
 *   A logger instance for recording validation steps or errors.
 *
 * @returns {Promise<
 *   import('zod').SafeParseSuccess<T> |
 *   import('zod').SafeParseError<T> |
 *   { valid: false; errors: object | string }
 * >}
 * Resolves with the parsed data on success (`SafeParseSuccess<T>`), or:
 * - a Zod `SafeParseError<T>` if Zod parsing failed, or
 * - an object `{ valid: false; errors }` if other validation checks failed.
 *
 * @see {@link ./validateZodSchema.js}
 *
 * @example
 * const result = await validateSchema(passwordSchema, req.body, req, log);
 * if ('valid' in result && result.valid === false) {
 *   // non-Zod validation error
 *   res.status(400).json({ error: result.errors });
 * } else if (!('success' in result) || result.success === false) {
 *   // Zod parsing error
 *   res.status(422).json(result.error.format());
 * } else {
 *   // Valid data
 *   const validatedData = result.data;
 * }
 */
export async function validateSchema<T, Input = unknown>(schema: ZodType<T, Input>,data: Input, req: Request, log: any): Promise<ZodSafeParseResult<T> 
| { valid: boolean; errors: object | string; }>  {
log.info(`Validating schema...`)
  const sch = schema.safeParse(data);
  if (!sch.success) {
     const htmlIssue = sch.error?.issues.find(issue => issue.message.startsWith('HTML found'))
     if (htmlIssue) {
        await handleXSS(req, htmlIssue.message, log)
        log.warn(`XSS attempt banned visitor.`)
        return {
            valid: false,
            errors: 'XSS attempt'
        };
     }
    const errors: Record<string,string> = {}
    sch.error.issues.forEach(issue => {
      const key = issue.path[0] as string
      log.info(`Schema error, data is not valid: ${issue}`)
      errors[`${key} Error`] = issue.message
    })
    return {
        valid: false,
        errors: errors
    }
    } 
    log.info(`Schema parsed`) 
    return sch;
  }


