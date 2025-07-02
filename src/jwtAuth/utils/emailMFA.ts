import { tempJwtLink } from "../../tempLinks.js";
import { mfaEmail } from "../utils/systemEmailMap.js";
import { pool } from "../config/dbConnection.js";
import { RowDataPacket } from "mysql2";
import crypto from 'crypto';
import { logger } from "../utils/logger.js";


export async function sendTempMfaLink(
user: { userId: number; visitor: number },
sessionToken: string,
): Promise<boolean> {
const jti = `${crypto.randomUUID()}${crypto.randomBytes(64).toString('hex')}`;
const log = logger.child({service: 'auth', branch: 'mfa', visitorId: user.visitor})
  const tempToken = tempJwtLink(
    { 
      visitor: user.visitor,   
      subject: 'MAGIC_LINK_MFA_CHECKS',
      purpose: 'MFA',
      jti: jti 
    }
  );
  log.info(`Entered mfa, generating temp link...`)
  const path = "/auth/verify-mfa";
  const url = `https://testing.com${path}/${user.visitor}?temp=${encodeURIComponent(tempToken)}`

  log.info(`Generating mfa code...`)
  const randomCode = crypto.randomInt(1000000, 9999999).toString().padStart(7, '0');
  const hashedCode = crypto.createHash("sha256").update(randomCode).digest("hex");
  const expires = new Date(Date.now() + 7 * 60 * 1000);
  const hashedClientToken = crypto.createHash('sha256').update(sessionToken).digest('hex');
  const params = [user.userId, hashedClientToken, jti, hashedCode, expires];
  const conn = await pool.getConnection();

  try { 
    
    await conn.beginTransaction();  

  const [exits] = await conn.execute<RowDataPacket[]>(`
    SELECT code_hash FROM mfa_codes
     WHERE user_id = ?
     AND token = ?
     AND expires_at > NOW() 
  `, [user.userId, hashedClientToken]);


    if (exits.length > 0) {
      log.info(`Valid MFA code found for user ${user.userId}: ${exits[0].code_hash}`)
      await conn.commit();
      return true;
    };

      await conn.execute(`
      DELETE FROM mfa_codes
      WHERE user_id = ?
    `, [user.userId]);    

   await conn.execute<RowDataPacket[]>(`
    INSERT INTO mfa_codes
    (user_id, token, jti, code_hash, expires_at)
    VALUES (?, ?, ?, ?, ?)
    `,params);
    await conn.commit();
   log.info(`Generated code`)
  
} catch(err) {
    log.error({err}, `error Generating code`)
    await conn.rollback();
    conn.release();
    return false;
} 
conn.release();
try {
  log.info(`Sending email...`)
  const [rows] = await pool.execute<RowDataPacket[]>(`SELECT name, email FROM users WHERE id = ?`, [user.userId]);
  const { name, email } = rows[0];
  await mfaEmail(name, Number(randomCode), email, url);
  log.info(`email sended.`)
  return true;
} catch (err) {
    log.error({err},`SMTP error in sendTempMfaLink`)
    return false;
  }
 }
