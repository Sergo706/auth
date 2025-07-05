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


const consecutiveForCompositeKey = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 10);
const consecutiveForIp = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 10);
export const consecutiveForjti = makeConsecutiveCache< {countData:number} >(2000, 1000 * 60 * 20);

export const verifyNewPassword = async (req: Request, res: Response, next: NextFunction) => {
  const log = getLogger().child({service: 'auth', branch: 'password-reset'})
  const { uniLimiter, ipLimit  } = getLimiters();
  log.info(`Verifing new password...`)

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
        res.status(400).json({error: `Password dosn't match`,  "banned": false })
        return;
 }
const pool = await getPool()
const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const hashedPassword = await hashPassword(password, log);
    const [findUser] = await conn.execute<RowDataPacket[]>(`
    SELECT id FROM users
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
    await ipLimit.block(req.link.jti!, 60 * 20);
    await conn.commit();

    log.info({visitorId: req.link.visitor, userId: findUser[0].id},`Reset password succesfuly`);
    consecutiveForCompositeKey.delete(compositeKey);
    consecutiveForIp.delete(req.ip!);
    await resetLimitersUni(compositeKey);
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