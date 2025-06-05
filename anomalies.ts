import { pool } from "../../config/dbConnection.js";
import { RowDataPacket } from 'mysql2';
import parseUA from '../botDetector/helpers/UAparser.js';
import { getdata } from '../botDetector/helpers/getIPInformation.js';
import ipRangeCheck from 'ip-range-check' 
import { revokeRefreshToken } from "./refreshTokens.js";
import { createHash } from "crypto";

interface RefreshRow {
  user_id:             number;
  valid:               boolean;
  expiresAt:           Date;
  created_at:          Date;
  usage_count:         number;
  visitor_id:          number;
  canary_id:           string;
  ip_address:          string;
  country:             string;
  city:                string;
  district:            string;
  lat:                 string;
  lon:                 string;
  timezone:            string;
  currency:            string;
  isp:                 string;
  org:                 string;
  as:                  string;
  device:              string;
  browser:             string;
  proxy:               boolean;
  hosting:             boolean;
  last_seen:           Date;
  deviceVendor:        string;
  deviceModel:         string;
  browserType:         string;
  os:                  string;
  suspicos_activity_score: number;
}


export async function strangeThings (token: string, cookie: string, ipAddress: string, ua: string, rotated: boolean):
Promise<boolean>{
const hashedClientToken = createHash('sha256').update(token).digest('hex');

const [rows] = await pool.execute<RowDataPacket[]>(`

SELECT 
            refresh_tokens.user_id, 
            refresh_tokens.valid, 
            refresh_tokens.expiresAt,
            refresh_tokens.created_at,
            refresh_tokens.usage_count,
            users.visitor_id,  
            visitors.ip_address,
            visitors.country,
            visitors.city,
            visitors.district,
            visitors.canary_id,
            visitors.lat,
            visitors.lon,
            visitors.timezone,
            visitors.currency,
            visitors.isp,
            visitors.org,
            visitors.as_org,
            visitors.device_type AS device,
            visitors.browser,
            visitors.proxy,
            visitors.hosting,
            visitors.last_seen,
            visitors.deviceVendor,
            visitors.deviceModel,
            visitors.browserType,
            visitors.browserVersion,
            visitors.os,
            visitors.suspicos_activity_score

      FROM refresh_tokens 
      JOIN users ON refresh_tokens.user_id = users.id
      JOIN visitors ON users.visitor_id = visitors.visitor_id
    WHERE refresh_tokens.token = ? LIMIT 1
    `, [hashedClientToken]);
   
  if (!rows || rows.length === 0) {
    console.log('revoked')
    return false;
  }

const tokenResults = rows[0] as RefreshRow;


if (!tokenResults.valid || rotated && tokenResults.usage_count > 0) { 
     await revokeRefreshToken(token)
     return false;   
};

  const [JustValidTokens] = await pool.execute<RowDataPacket[]>(`
 SELECT COUNT(*) AS totalValid,
   SUM(created_at >= NOW() - INTERVAL 10 MINUTE) AS recentValid
   FROM refresh_tokens
 WHERE user_id = ?
  AND valid = 1
    `, [tokenResults.user_id]); 

  if (JustValidTokens && JustValidTokens.length > 0) {
    const results = JustValidTokens[0];
        if(results.totalValid >= 5) {
            await revokeRefreshToken(token)
            return false;   
        }
        
        if(results.recentValid > 3) {
         await revokeRefreshToken(token)
         return false;  
        }
  };


if (tokenResults.canary_id !== cookie) { 
    await revokeRefreshToken(token); 
    return false;
 }

  const isInRange = ipRangeCheck(tokenResults.ip_address, ipAddress);
    if (!isInRange) { 
    await revokeRefreshToken(token)
    return false;   
    };


    if (tokenResults.suspicos_activity_score >= 9) { 
        await revokeRefreshToken(token); 
        return false;  
    };

    const day = 1000 * 60 * 60 * 24;
    if (Date.now() - tokenResults.last_seen.getTime() > day) { 
        await revokeRefreshToken(token); 
        return false;  
    };


const [incomingGeo] = await Promise.all([ getdata(ipAddress) ]);
const incomingParsedUA = parseUA(ua);

    if (incomingGeo.proxy || incomingGeo.hosting) { 
        await revokeRefreshToken(token); 
        return false;  
    };


    const { proxy, hosting, ...restOfGeo} = incomingGeo;
    const incomingReq = Object.assign(incomingParsedUA, restOfGeo);

for (const [reqKey, reqValue] of Object.entries(incomingReq)) {
  if ((reqKey in tokenResults)) {
    const userValue = (tokenResults as any)[reqKey];
    const notNull = 
    reqValue !== undefined && 
    userValue !== undefined && 
    userValue &&
    reqValue && 
    reqValue !== 'unknown' &&
    userValue !== 'unknown';
    if (notNull && reqValue !== userValue) {
      await revokeRefreshToken(token);
      return false;
    }
  }
}

return true;

}


