import { ZodType, ZodSafeParseResult } from "zod/v4";
import { handleXSS } from "./handleXSS.js";
import { Request } from "express";

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


