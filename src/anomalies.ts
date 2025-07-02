import { pool } from "./jwtAuth/config/dbConnection.js";
import { RowDataPacket } from 'mysql2';
import parseUA from '../../botDetector/helpers/UAparser.js';
import { getdata } from '../../../botDetector/helpers/getIPInformation.js';
import ipRangeCheck from 'ip-range-check' 
import { revokeRefreshToken } from "./refreshTokens.js";
import { createHash } from "crypto";
import { logger } from "./jwtAuth/utils/logger.js";


interface RefreshRow {
  user_id:             number;
  valid:               boolean;
  expiresAt:           Date;
  created_at:          Date;
  usage_count:         number;
  visitor_id:          number;
  last_mfa_at:         Date;
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
  proxy_allowed:       boolean;
  hosting:             boolean;
  hosting_allowed:     boolean;
  last_seen:           Date;
  deviceVendor:        string;
  deviceModel:         string;
  browserType:         string;
  os:                  string;
  suspicos_activity_score: number;
}


export async function strangeThings (token: string, cookie: string, ipAddress: string, ua: string, rotated: boolean):
Promise <{
  valid: boolean;
  reason: string;
  reqMFA: boolean;
  userId?: number;
  visitorId?: number;
}>

{
const hashedClientToken = createHash('sha256').update(token).digest('hex');
const log = logger.child({service: 'auth', branch: 'anomalies', visitor_cookie: cookie, ip:ipAddress});
const [rows] = await pool.execute<RowDataPacket[]>(`

SELECT 
            refresh_tokens.user_id, 
            refresh_tokens.valid, 
            refresh_tokens.expiresAt,
            refresh_tokens.created_at,
            refresh_tokens.usage_count,
            users.visitor_id,
            users.last_mfa_at,  
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
            visitors.proxy_allowed,
            visitors.hosting,
            visitors.hosting_allowed,
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
   log.warn('No valid token was found')
    return {
      valid: false,
      reason: 'No token found',
      reqMFA: false
    };
  }

const tokenResults = rows[0] as RefreshRow;


if (!tokenResults.valid || rotated && tokenResults.usage_count > 0) { 
     await revokeRefreshToken(token)
     log.info('token is invalid or being used more then ones')
      return {
      valid: false,
      reason: 'token is invalid or being used more then ones',
      reqMFA: false
    };
};

if (tokenResults.canary_id !== cookie) { 
  log.info(`canary cookies dosn't match. DB cookie: ${tokenResults.canary_id}, incoming cookie ${cookie}`)
    return {
      valid: false,
      reason: 'new device',
      reqMFA: true,
      userId: tokenResults.user_id,
      visitorId: tokenResults.visitor_id
    };
 }

    const day = 1000 * 60 * 60 * 24;
    if (Date.now() - tokenResults.last_seen.getTime() > day) { 
       log.info(`time last seen has been triggered. Time ${Date.now()} Last seen: ${tokenResults.last_seen.getTime()}`)
        return {
          valid: false,
          reason: 'idle',
          reqMFA: true,
          userId: tokenResults.user_id,
          visitorId: tokenResults.visitor_id
        };  
    };
    
  const [JustValidTokens] = await pool.execute<RowDataPacket[]>(
  `SELECT
     (SELECT COUNT(*) FROM refresh_tokens
       WHERE user_id = ? AND valid = 1) AS totalValid,

     (SELECT SUM(created_at >= NOW() - INTERVAL 10 MINUTE)
       FROM refresh_tokens
       WHERE user_id = ? AND valid = 1) AS recentValid,

     users.last_mfa_at

   FROM users 
   WHERE users.id = ?`, [tokenResults.user_id, tokenResults.user_id,tokenResults.user_id]); 

  if (JustValidTokens && JustValidTokens.length > 0) {
    const results = JustValidTokens[0];

  const bypass =
  results.last_mfa_at &&
  Date.now() - new Date(results.last_mfa_at).getTime() < 10 * 60 * 1000; 

  if(results.totalValid >= 5 && !bypass) {
   log.info(`more than 5 active sessions`)   
    return {
      valid: false,
      reason: 'more than 5 active sessions',
      reqMFA: true,
      userId: tokenResults.user_id,
      visitorId: tokenResults.visitor_id
    };   
        }
        
        if (results.recentValid > 3) {
         await revokeRefreshToken(token)
          log.warn(`3 tokens in less than 10 min`)     
         return {
          valid: false,
          reason: '3 tokens in less than 10 min',
          reqMFA: false
         };  
        }
  };


  const isInRange = ipRangeCheck(tokenResults.ip_address, ipAddress);
    if (!isInRange) { 
      log.info(`Ip does not match`)   
    return {
      valid: false,
      reason: 'Ip does not match',
      reqMFA: true,
      userId: tokenResults.user_id,
      visitorId: tokenResults.visitor_id
    }  
    };


    if (tokenResults.suspicos_activity_score >= 9) { 
            log.info(`Suspicos score to high`)  
        return {
          valid: false,
          reason: 'Suspicos score to high',
          reqMFA: true,
          userId: tokenResults.user_id,
          visitorId: tokenResults.visitor_id
        }  
    };


const [incomingGeo] = await Promise.all([ getdata(ipAddress) ]);
const incomingParsedUA = parseUA(ua);

    if (incomingGeo.proxy || incomingGeo.hosting) {
      log.info(`Proxy Or hosting detected`)  
        const proxyAllowed    = !!tokenResults.proxy_allowed; 
        const hostingAllowed  = !!tokenResults.hosting_allowed;

        if ((incomingGeo.proxy && !proxyAllowed) ||
      (incomingGeo.hosting && !hostingAllowed)) {
        log.info({userId: tokenResults.user_id},`Proxy Or hosting is not allowed for this user.`)  
        return {
          valid: false,
          reason: 'Proxy Or hosting',
          reqMFA: true,
          userId: tokenResults.user_id,
          visitorId: tokenResults.visitor_id
        }  
    };
    
    log.info({userId: tokenResults.user_id},`Proxy Or hosting is allowed for this user.`)  
    return {
    valid: true,
    reason: 'Proxy or hosting allowed',
    reqMFA: false
    }
}
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
      log.info({user_value: userValue, reqValue: reqValue}, `Loop detected an missmatch`)  
        return {
          valid: false,
          reason: 'Loop detected',
          reqMFA: true,
          userId: tokenResults.user_id,
          visitorId: tokenResults.visitor_id
        }  
    }
  }
}
log.info(`Checks passed`)
return {
  valid: true,
  reason: 'Checks passed',
  reqMFA: false
}

}


