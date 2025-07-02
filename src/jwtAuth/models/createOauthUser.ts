import { ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { pool } from "../config/dbConnection.js";
import { sendLog } from "../utils/telegramLogger.js";
import { OauthUser } from "../types/newUser.js";
import { NewUserGoogle } from "./zodSchemaGoogle.js";
import { generateAccessToken } from "../../accsessTokens.js";
import { generateRefreshToken } from "../../refreshTokens.js";
import { IssuedRefreshToken } from "../../refreshTokens.js";
import { config } from "../config/secret.js";
import { logger } from "../utils/logger.js";


export async function createOauthUser(cookie: string, data: NewUserGoogle): 
Promise <  
{ success: boolean;  accessToken?: string; refreshToken?: IssuedRefreshToken; duplicate?: true;  }
> {  
    const log = logger.child({service: 'auth', branch: 'oauth'});

    if (!cookie) {
        log.error(`createOauthUser, cookie is undefined:', ${cookie}`)
        throw new Error(`cookie is undefined `)
    }
  

    try {
    const [visitorsData]  = await pool.execute<RowDataPacket[]>
    ("SELECT country, city , district, visitor_id  FROM visitors WHERE canary_id = ?", [cookie]);
    const results = visitorsData[0];   

        if (results) {
           const payload: OauthUser = {
               ...data,
               country: results.country === 'unknown' ? null : results.country,
               city: results.city === 'unknown' ? null : results.city,
               district: results.district === 'unknown' ? null : results.district,
               visitor_id: results.visitor_id,
            }
            const { 
                sub,
                email,
                picture,
                name,
                given_name,
                family_name,
                country,
                city,
                district,
                visitor_id
             } = payload;

        const stm = `INSERT INTO users 
        (name, last_name, email, avatar, password_hash, provider, provider_id,  remember_user, terms_and_privacy_agreement, country, city,
        district, visitor_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

     const params = [name, given_name ?? family_name ?? 'unknown', email, picture, 'no_password', 'google', sub, true, true, country, city, district, visitor_id]
     const [newUser] = await pool.execute<ResultSetHeader>(stm, params);  
     const newUserId =  newUser.insertId;

    const refresh = await generateRefreshToken(config.auth.jwt.refresh_ttl,  newUserId);
    const accessToken = generateAccessToken({id: newUserId, visitor_id: results.visitor_id, jti: crypto.randomUUID()});
     log.info(`New User created succsesfuly!`)        
    sendLog('New User created', `New User created succsesfuly!`);

     return {
     success: true,
     accessToken: accessToken,
     refreshToken: refresh
  }

    }
        } catch(err) {
        const mysqlErr = err as any;
         if (mysqlErr.code === 'ER_DUP_ENTRY') {
             log.error({err},`mysql failed`) 
             return { success: false, duplicate: true };
         }
        log.error({err},`Failed to Create New User`) 
        sendLog('Failed to Create New User', `Error: ${err}`)
        return {success: false};
    }
return {success: false}

}