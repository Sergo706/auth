import { ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { getPool } from "../config/dbConnection.js";
import { sendLog } from "../utils/telegramLogger.js";
import { User } from "../types/newUser.js";
import { NewUser } from "./zodSignUpSchemas.js";
import { generateAccessToken } from "../../accessTokens.js";
import { generateRefreshToken } from "../../refreshTokens.js";
import { IssuedRefreshToken } from "../../refreshTokens.js";
import { getConfiguration } from "../config/configuration.js";
import { getLogger } from "../utils/logger.js";
import crypto from 'crypto';


/**
 * @description
 * Create a new local user account.
 *
 * @param {string} cookie
 *   The `canary_id` cookie value from the client.
 * @param {import('./jwtAuth/types/newUser.js').NewUser} data
 *   The new user’s registration details.
 *
 * @returns {Promise<{
 *   success: boolean;
 *   accessToken?: string;
 *   refreshToken?: IssuedRefreshToken;
 *   duplicate?: true;
 * }>}
 * Resolves with an object indicating whether creation succeeded. If a user with the same
 * credentials already exists, `duplicate` will be `true`. On success, issued tokens are returned.
 *
 * @example
 * import { NewUser } from './jwtAuth/types/newUser.js';
 *
 * const data: NewUser = { email: 'alice@example.com', password: 's3cr3t' };
 * const result = await createUser(req.cookies.canary_id, data);
 * if (result.success) {
 *   console.log('Access Token:', result.accessToken);
 * } else if (result.duplicate) {
 *   console.warn('User already exists');
 * }
 *
 * @see {@link ./models/createUser.js}
 */
export async function createUser(cookie: string, data: NewUser): 
Promise<  
{ success: boolean;  accessToken?: string; refreshToken?: IssuedRefreshToken; duplicate?: true;  }
> {  
    const pool = getPool()
    const log = getLogger().child({service: 'auth', branch: 'classic', type: 'signup'});
    const { jwt } = getConfiguration();
    log.info(`Creating user...`)
    try {
        const [visitorsData]  = await pool.execute<RowDataPacket[]>
        ("SELECT country, city , district, visitor_id  FROM visitors WHERE canary_id = ?", [cookie]);
        const results = visitorsData[0];   
        log.info(`Got visitor data. proceeding to user creation...`)
        if (results) {
           const payload: User = {
               ...data,
               country: results.country === 'unknown' ? null : results.country,
               city: results.city === 'unknown' ? null : results.city,
               district: results.district === 'unknown' ? null : results.district,
               visitor_id: results.visitor_id,
            }
            const { Name, confirmedPassword, ...restPayload } = payload;
            const userNames = Name.replace(/\s{2,}/g, ' ').split(/\s*,\s*|\s+/).filter(Boolean);
            const [name = '', ...rest] = userNames;
            const lastname = rest.join(' ');


            const stm = `INSERT INTO users 
            (name, last_name, email, password_hash, remember_user, terms_and_privacy_agreement, country, city,
            district, visitor_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `;
          
            const params = [name, lastname, Object.values(restPayload)].flat()
            const [newUser] = await pool.execute<ResultSetHeader>(stm, params);  
            const newUserId =  newUser.insertId;
            log.info(`User created, isussing tokens...`)
            const refresh = await generateRefreshToken(jwt.refresh_tokens.refresh_ttl,  newUserId);
            const accessToken = generateAccessToken({id: newUserId, visitor_id: results.visitor_id, jti: crypto.randomUUID()});
            log.info(`New User created succsesfuly!`)
            sendLog('New User created', `New User created succsesfuly!`)
        return {
            success: true,
            accessToken: accessToken,
            refreshToken: refresh
        }
        
        }         
    } catch(err) {
        const mysqlErr = err as any;
         if (mysqlErr.code === 'ER_DUP_ENTRY') {
             log.error({err},`mysql failed`);
             return { success: false, duplicate: true };
         }
        log.error({err},`Failed to Create New User`);
        sendLog('Failed to Create New User', `${err}`)
        return {success: false};
    }
    
return {success: false}
}
