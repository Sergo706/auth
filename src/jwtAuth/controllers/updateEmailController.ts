import { NextFunction, Request, Response } from "express";
import { getLogger } from "../utils/logger.js";
import { verifyMfaCode } from "../utils/verifyMfaCode.js";
import { getPool } from "../config/configuration.js";
import { validateSchema } from "../utils/validateZodSchema.js";
import { guard } from "../utils/limiters/utils/guard.js";
import { dataSchema } from "../types/UpdateEmail.js";
import { verifyPassword } from "../utils/hash.js";
import { ResultSetHeader, RowDataPacket } from "mysql2";
import { sendEmailNotification } from "../utils/systemEmailMap.js";
import { getConfiguration } from "../config/configuration.js";
import { getLimiters} from "../utils/limiters/protectedEndpoints/tempPostRoutesLimiter.js";
import { makeConsecutiveCache } from "../utils/limiters/utils/consecutiveCache.js";

const consecutiveForSlowDown = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 10);

export async function updateEmailController(req: Request, res: Response, next: NextFunction) {
  const log = getLogger().child({service: 'auth', branch: 'custom-mfa', visitorId: req.newVisitorId ?? req.link.visitor, reason: req.link.purpose})
  
  log.info(`Verifying mfa code and updating email...`)

 if (!req.is('application/json')) {
    log.warn('Content type is not json!')
    res.status(400).json({error: 'Bad Request.'})
    return; 
  }
     const { visitor_id, userId } = req.user!;

     if (!visitor_id || !userId) {
         log.info('Session is invalid')
         res.status(400).json({
             ok:false,
             date: new Date().toISOString(), 
             reason: 'Invalid email or password'
         })
         return;
     }

     const { uniLimiter } = getLimiters();
     if (!(await guard(uniLimiter, userId, consecutiveForSlowDown, 2, 'SlowDown', log, res))) return;



  if (req.link.purpose !== "change_email" || visitor_id !== req.link.visitor) {
    log.warn('Invalid link purpose/Email is null')
     res.status(400).json({ 
        ok: false, 
        date: new Date().toISOString(), 
        reason: 'Invalid email or password' 
      });
    return;
  }
    
    const result = await validateSchema(dataSchema, req.body, req, log)

   if ("valid" in result) { 
     if (!result.valid && result.errors !== 'XSS attempt') {
        res.status(400).json(Object.assign({error: result.errors,  "banned": false }))
        return;
     }
     res.status(403).json({"banned": true})
     return; 
 } 

    if (!result.success) {
          log.error({ errors: result.error }, "Zod validation failed")
          res.status(400).json({ 
              ok: false,
              date: new Date().toISOString(), 
              reason: "Zod validation failed malformed link"
           })
          return;
     }

 const {email, newEmail, password} = result.data;
 let name: string = '';
 const pool = getPool();

 try {
    const [user] = await pool.execute<RowDataPacket[]>(`
        SELECT email, password_hash AS hashed_password, name FROM users
         WHERE email = ?
            AND visitor_id = ?
            AND id = ?
        `,[email, visitor_id, userId]) ;

        if (!user || user.length === 0) {
            log.info(`User doesn't exists..`)
            await pool.rollback()
            res.status(400).json({
                ok:false,
                date: new Date().toISOString(), 
                reason: 'Invalid email or password'  
            })
            return;
        }

        log.info(`Found user, validating password...`)
        const { hashed_password, username } = user[0] ;
        name = username;
        const isPasswordValid = await verifyPassword(hashed_password, password);

        if (!isPasswordValid) {
            log.warn(`Password is not valid.`) 
            res.status(400).json({
                ok: false, 
                date: new Date().toISOString(),
                reason: 'Invalid email or password'
            })
            return;
        }

 } catch (error) {
     log.error({error}, "Error verifying password or checking user")
      res.status(500).json({ 
            ok: false,
            date: new Date().toISOString(),
            reason: 'Internal server error'
      });
      return;
  }

 return await verifyMfaCode(req, res, next, req.body.code, log, false, true, async (conn, userId) => {
    const [results] = await conn.execute<ResultSetHeader>(`
                UPDATE users
                  SET email = ?
                WHERE id = ?
                AND email = ?
            `,[newEmail, userId, email])
    if (results.affectedRows !== 1) {
        throw new Error('Failed to update email')  
    }

    const { magic_links } = getConfiguration()
    const {contactPageLink} = magic_links.notificationEmail
    await sendEmailNotification(email, name, {
        title: "Your Email Has Changed",
        action: "Notice of Change",
        subject: "Security Alert: Email Address Updated",
        message: `Your account's email address has been updated to <b>${newEmail}</b>. <br/>If you did not authorize this change, please contact support immediately to secure your account.`,
        cta: "Contact Support",
        cta_link: contactPageLink,
    })
 });
}