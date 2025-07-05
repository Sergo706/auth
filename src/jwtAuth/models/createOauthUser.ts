import { ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { getPool } from "../config/dbConnection.js";
import { sendLog } from "../utils/telegramLogger.js";
import { OauthUser } from "../types/newUser.js";
import { NewUserGoogle } from "./zodSchemaGoogle.js";
import { generateAccessToken } from "../../accsessTokens.js";
import { generateRefreshToken } from "../../refreshTokens.js";
import { IssuedRefreshToken } from "../../refreshTokens.js";
import { getConfiguration } from "../config/configuration.js";
import { getLogger } from "../utils/logger.js";
import { StandardProfile } from "../utils/newOauthProvider.js";

export async function createOauthUser(cookie: string, data: StandardProfile, provider: string): 
Promise <  
{ success: boolean;  accessToken?: string; refreshToken?: IssuedRefreshToken; duplicate?: true;  }
> {  
    const log = getLogger().child({service: 'auth', branch: 'oauth'});

    if (!cookie) {
        log.error(`createOauthUser, cookie is undefined:', ${cookie}`)
        throw new Error(`cookie is undefined `)
    }
const { jwt } = getConfiguration();  
const pool = await getPool()
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
                name,
                last_name,  
                sub,
                email,
                avatar,
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

     const params = [
        name ?? given_name ?? null,
        family_name ?? last_name ?? null,
        email,
        avatar ?? null,
        'no_password',
        provider,
        sub,
        true,
        true,
        country,
        city,
        district,
        visitor_id
    ]
     const [newUser] = await pool.execute<ResultSetHeader>(stm, params);  
     const newUserId =  newUser.insertId;

    const refresh = await generateRefreshToken(jwt.refresh_tokens.refresh_ttl,  newUserId);
    const accessToken = generateAccessToken({id: newUserId, visitor_id: results.visitor_id, jti: crypto.randomUUID()});
     log.info(`New User created successfully!`)        
    sendLog('New User created', `New User created successfully!`);

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