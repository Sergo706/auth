import { hashPassword } from "../utils/hash.js";
import { Request, Response, NextFunction } from "express";
import { getPool } from "../config/dbConnection.js";
import { passwords } from "../models/zodSchema.js";
import { ResultSetHeader, RowDataPacket } from "mysql2";
import { getLogger } from "../utils/logger.js";
import { validateSchema } from "../utils/validateZodSchema.js";
import { guard } from "../utils/limiters/utils/guard.js";
import { getLimiters, resetLimitersUni } from "../utils/limiters/protectedEndpoints/tempPostRoutesLimiter.js";
import { makeConsecutiveCache } from "../utils/limiters/utils/consecutiveCache.js";
import { sendEmailNotification } from "../utils/systemEmailMap.js";
import { getConfiguration } from "../config/configuration.js";


const consecutiveForCompositeKey = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 10);
const consecutiveForIp = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 10);
export const consecutiveForjti = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 20);

/**
 * @description
 * Verifies the “reset password” token (e.g., from an emailed link), ensures
 * it’s valid and not expired.  
 * On success, sends `res.status(200).json({ success: true })` and skips to the next handler.
 * On failure, calls `next(err)` to pass control to your error handler.
 *
 * @name verifyNewPassword
 * @function
 * @param {import('express').Request} req
 *   The Express request object.
 * @param {import('express').Response} res
 *   The Express response object.
 * @param {import('express').NextFunction} next
 *   The next middleware function.
 *
 * @returns {Promise<void>}
 *   Resolves after sending a JSON response or invoking `next` on error.
 *
 * @see {@link ./middleware/verifyPasswordReset.js}
 *
 * @example
 * app.post('/password/reset', verifyNewPassword, (req, res) => {
 *   // If verification succeeded, you reach here
 *   res.redirect('/login');
 * });
 */
export const verifyNewPassword = async (req: Request, res: Response, next: NextFunction) => {
  const log = getLogger().child({service: 'auth', branch: 'password-reset'})
  const { uniLimiter, ipLimit, usedJtiLimiter  } = getLimiters();
  log.info(`Verifying new password...`)

if (!req.is('application/json')) {
    log.warn('Content type is not json!')
    res.status(400).json({error: 'Bad Request.'})
    return; 
  }
  
  if (req.link.purpose !== "PASSWORD_RESET" && req.link.subject !== 'MAGIC_LINK_Restart') {
    log.warn('Invalid link purpose/Email is null')
     res.status(400).json({ error: "Invalid link purpose/Email is null" });
    return;
  }

  if (!(await guard(ipLimit, req.link.jti!, consecutiveForjti, 1, 'jti for new password', log, res))) return;
  if (!(await guard(ipLimit, req.ip!, consecutiveForIp, 2, 'Ip', log, res))) return;

  const compositeKey = `${req.ip}_${req.link.visitor}`;
  if (!(await guard(uniLimiter, compositeKey, consecutiveForCompositeKey, 2, 'compositeKey', log, res))) return;


  const result = await validateSchema(passwords, req.body, req, log)

 if ("valid" in result) { 
     if (!result.valid && result.errors !== 'XSS attempt') {
        res.status(400).json(Object.assign({error: result.errors,  "banned": false }))
        return;
     }
     res.status(403).json({"banned": true})
     return; 
 } 
 const {confirmedPassword, password} = result.data!;

 if (confirmedPassword !== password) {
        log.info(`Passwords didnt match.`)
        res.status(400).json({error: `Password doesn't match`,  "banned": false })
        return;
 }
const pool = getPool()
const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const hashedPassword = await hashPassword(password, log);
    const [findUser] = await conn.execute<RowDataPacket[]>(`
    SELECT id, email, name FROM users
      WHERE visitor_id = ?
      LIMIT 1  
    FOR UPDATE 
      `,[req.link.visitor]);

      if (!findUser || findUser.length === 0) {
        await conn.rollback();
        log.warn({visitorId: req.link.visitor},`Invalid link purpose/Email`)
        res.status(400).json({ error: "Invalid link purpose/Email" });
        return;
      }

 const [result] = await conn.execute<ResultSetHeader>(`
        UPDATE users
        SET password_hash = ?
        WHERE id = ?
        AND visitor_id = ?
        LIMIT 1
        `,[hashedPassword, findUser[0].id, req.link.visitor])

    if (result.affectedRows !== 1) {
      await conn.rollback();
      log.warn({visitorId: req.link.visitor},`Reset link invalid or already used.`)
     res.status(400).json({ error: 'Reset link invalid or already used.' });
     return;
}

  await conn.execute<ResultSetHeader>(`
    UPDATE refresh_tokens
     SET valid = 0
     WHERE user_id = ?
     AND valid = 1
     AND user_id IS NOT NULL
    `,[findUser[0].id])
    await usedJtiLimiter.block(req.link.jti!, 60 * 20);
    await conn.commit();

    log.info({visitorId: req.link.visitor, userId: findUser[0].id},`Reset password successfully`);
    consecutiveForCompositeKey.delete(compositeKey);
    consecutiveForIp.delete(req.ip!);
    await resetLimitersUni(compositeKey);
    const { magic_links } = getConfiguration()

    await sendEmailNotification(findUser[0].email, findUser[0].name, {
        title: "Password Reset Successful",
        action: "Security Notification",
        subject: "Security Alert: Password Reset Successful",
        message: `Your account password has been successfully reset. <br/>If you did not authorize this change, please contact support immediately.`,
        cta: "Go to Login",
        cta_link: `${magic_links.domain}/accounts`, 
    })
   res.status(200).json({ success: true });
   return;

  } catch (err) {
    await conn.rollback();
    log.error({err},`Password reset error`)
     res.status(500).json({ error: "Internal server error" });
    return;
  } finally {
  conn.release();
}
  }