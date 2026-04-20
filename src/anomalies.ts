import { getPool } from "./jwtAuth/config/configuration.js";
import { RowDataPacket } from 'mysql2';
import { getGeoData, parseUA } from '@riavzon/bot-detector';
import ipRangeCheck from 'ip-range-check' 
import { revokeRefreshToken } from "./refreshTokens.js";
import { createHash } from "crypto";
import { getLogger } from "./jwtAuth/utils/logger.js";
import { getConfiguration } from "./jwtAuth/config/configuration.js";
import { anomaliesCache } from "~~/utils/anomaliesCache.js";

interface RefreshRow {
  user_id:             number;
  valid:               boolean;
  expiresAt:           Date;
  created_at:          Date;
  usage_count:         number;
  visitor_id:          string;
  last_mfa_at:         Date;
  canary_id:           string;
  userAgent:           string;
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
  suspicious_activity_score: number;
}

/**
 * @description
 * Anomaly-detection utility implementing bot-detection heuristics, IP differences,
 * device differences, and more. Use this to determine if a refresh token use
 * should trigger MFA or block the session.
 *
 * @param {string} token - The raw or hashed refresh token to inspect.
 * @param {string} cookie - The `canary_id` cookie value from the client.
 * @param {string} ipAddress - The client’s IP address.
 * @param {string} ua - The client’s User-Agent string.
 * @param {boolean} rotated - Whether the refresh token has already been rotated.
 *
 * @returns {Promise<{
 *   valid: boolean;
 *   reason: string;
 *   reqMFA: boolean;
 *   userId?: number;
 *   visitorId?: number;
 * }>}
 * Resolves with an object indicating:
 * - `valid`: whether the request passes anomaly checks  
 * - `reason`: description of any anomaly detected  
 * - `reqMFA`: if true, require MFA before proceeding  
 * - `userId` / `visitorId`: IDs to associate on success  
 *
 * @see {@link ./anomalies.js}
 *
 * @example
 * const { valid, reason, reqMFA, userId, visitorId } = await strangeThings(
 *   rawRefreshToken,
 *   canary_id,
 *   req.ip!,
 *   req.get('User-Agent')!,
 *   false
 * );
 * if (!valid && reqMFA) {
 *   // prompt for MFA
 * } else if (!valid) {
 *   // block or log anomaly
 * }
 */     
export async function strangeThings (token: string, cookie: string, ipAddress: string, ua: string, rotated: boolean):
Promise <{
  valid: boolean;
  reason: string;
  reqMFA: boolean;
  userId?: number;
  visitorId?: string;
}>

{
const log = getLogger().child({service: 'auth', branch: 'anomalies', visitor_cookie: cookie, ip:ipAddress});

const cache = anomaliesCache()

const pool = getPool()
const hashedClientToken = createHash('sha256').update(token).digest('hex');
const cached = cache?.get(hashedClientToken);

if (cached && !cached.resolved) {
  log.info({cached}, 'User anomaly is already in progress or this session is invalid')
  return {
    valid: false,
    reason: cached.anomalyType,
    reqMFA: cached.resolvable,
    visitorId: cached.visitorId,
    userId: cached.userId
  }
}
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
            visitors.user_agent AS userAgent,
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
            visitors.suspicious_activity_score

      FROM refresh_tokens 
      JOIN users ON refresh_tokens.user_id = users.id
      JOIN visitors ON users.visitor_id = visitors.visitor_id
    WHERE refresh_tokens.token = ? LIMIT 1
    `, [hashedClientToken]);

  if (!rows || rows.length === 0) {
   log.warn('No valid token was found')
   cache?.set(hashedClientToken, {
        anomalyType: 'No token found',
        canaryCookie: cookie,
        resolved: false,
        resolvable: false,
   })
    return {
      valid: false,
      reason: 'No token found',
      reqMFA: false
    };
  }

const tokenResults = rows[0] as RefreshRow;
const { refresh_tokens } = getConfiguration().jwt;

if (!tokenResults.valid || rotated && tokenResults.usage_count > 0) { 
     await revokeRefreshToken(token)
     log.info('token is invalid or being used more then ones')

     cache?.set(hashedClientToken, {
        anomalyType: "token is invalid or being used more then ones",
        canaryCookie: cookie,
        resolved: false,
        resolvable: false,
     })

      return {
        valid: false,
        reason: 'token is invalid or being used more then ones',
        reqMFA: false
    };
};

if (tokenResults.canary_id !== cookie) { 
  log.info(`canary cookies doesn't match. DB cookie: ${tokenResults.canary_id}, incoming cookie ${cookie}`)
  cache?.set(hashedClientToken, {
        anomalyType: 'new device',
        canaryCookie: cookie,
        resolved: false,
        resolvable: true,
        userId: tokenResults.user_id,
        visitorId: tokenResults.visitor_id
  })
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
      cache?.set(hashedClientToken, {
          anomalyType: 'idle',
          canaryCookie: cookie,
          resolved: false,
          resolvable: true,
          userId: tokenResults.user_id,
          visitorId: tokenResults.visitor_id
      })
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

     (SELECT SUM(created_at >= UTC_TIMESTAMP() - INTERVAL 10 MINUTE)
       FROM refresh_tokens
       WHERE user_id = ? AND valid = 1) AS recentValid,

     users.last_mfa_at

   FROM users 
   WHERE users.id = ?`, [tokenResults.user_id, tokenResults.user_id,tokenResults.user_id]); 

  if (JustValidTokens && JustValidTokens.length > 0) {
    const results = JustValidTokens[0];

  const bypass =
  results.last_mfa_at &&
  Date.now() - new Date(results.last_mfa_at).getTime() < refresh_tokens.byPassAnomaliesFor; 

  if(results.totalValid >= refresh_tokens.maxAllowedSessionsPerUser && !bypass) {
   log.info(`more than ${refresh_tokens.maxAllowedSessionsPerUser} active sessions`)
   cache?.set(hashedClientToken, {
          anomalyType: `more than ${refresh_tokens.maxAllowedSessionsPerUser} active sessions`,
          canaryCookie: cookie,
          resolved: false,
          resolvable: true,
          userId: tokenResults.user_id,
          visitorId: tokenResults.visitor_id
    })

    return {
      valid: false,
      reason: `more than ${refresh_tokens.maxAllowedSessionsPerUser} active sessions`,
      reqMFA: true,
      userId: tokenResults.user_id,
      visitorId: tokenResults.visitor_id
    };   
        }
        
        if (results.recentValid > 3) {
         await revokeRefreshToken(token)
          log.warn(`3 tokens in less than 10 min`)
           cache?.set(hashedClientToken, {
              anomalyType: `3 tokens in less than 10 min`,
              canaryCookie: cookie,
              resolved: false,
              resolvable: false,
          }) 
         return {
          valid: false,
          reason: '3 tokens in less than 10 min',
          reqMFA: false
         };  
        }
  };


  const isInRange = ipRangeCheck(ipAddress, tokenResults.ip_address,);
    if (!isInRange) { 
      log.info(`Ip does not match`)   
      cache?.set(hashedClientToken, {
          anomalyType: 'Ip does not match',
          canaryCookie: cookie,
          resolved: false,
          resolvable: true,
          userId: tokenResults.user_id,
          visitorId: tokenResults.visitor_id
      }) 
      return {
        valid: false,
        reason: 'Ip does not match',
        reqMFA: true,
        userId: tokenResults.user_id,
        visitorId: tokenResults.visitor_id
      }  
    };

    const config = getConfiguration()

      // @ts-ignore
    const maxScore = Number(config.botDetector.settings?.banScore ?? 100);
    
    if (tokenResults.suspicious_activity_score >= (maxScore * 0.25)) { 
        log.info(`Suspicion score to high`)  
        cache?.set(hashedClientToken, {
            anomalyType: 'Suspicion score to high',
            canaryCookie: cookie,
            resolved: false,
            resolvable: true,
            userId: tokenResults.user_id,
            visitorId: tokenResults.visitor_id
        }) 
        return {
          valid: false,
          reason: 'Suspicion score to high',
          reqMFA: true,
          userId: tokenResults.user_id,
          visitorId: tokenResults.visitor_id
        }  
    };


const [incomingGeo] = await Promise.all([ getGeoData(ipAddress) ]);
const incomingParsedUA = parseUA(ua);
const userAgent = ua;
    if (incomingGeo.proxy || incomingGeo.hosting) {
      log.info(`Proxy Or hosting detected`)  
        const proxyAllowed    = !!tokenResults.proxy_allowed; 
        const hostingAllowed  = !!tokenResults.hosting_allowed;

        if ((incomingGeo.proxy && !proxyAllowed) ||
      (incomingGeo.hosting && !hostingAllowed)) {
        log.info({userId: tokenResults.user_id},`Proxy Or hosting is not allowed for this user.`)  
        
        cache?.set(hashedClientToken, {
            anomalyType: 'Proxy Or hosting',
            canaryCookie: cookie,
            resolved: false,
            resolvable: true,
            userId: tokenResults.user_id,
            visitorId: tokenResults.visitor_id
        }) 

        return {
          valid: false,
          reason: 'Proxy Or hosting',
          reqMFA: true,
          userId: tokenResults.user_id,
          visitorId: tokenResults.visitor_id
        }  
    };
    
    log.info({userId: tokenResults.user_id},`Proxy Or hosting is allowed for this user.`)  
    cache?.set(hashedClientToken, {
            anomalyType: 'Proxy or hosting allowed',
            canaryCookie: cookie,
            resolved: true,
            resolvable: false,
            userId: tokenResults.user_id,
            visitorId: tokenResults.visitor_id
    }) 
    return {
      valid: true,
      reason: 'Proxy or hosting allowed',
      reqMFA: false
    }
}
    const { proxy, hosting, ...restOfGeo} = incomingGeo;
    const incomingReq = Object.assign(incomingParsedUA, restOfGeo, userAgent);

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
      log.info({user_value: userValue, reqValue: reqValue}, `Loop detected an mismatch`)

        cache?.set(hashedClientToken, {
            anomalyType: 'Loop detected',
            canaryCookie: cookie,
            resolved: false,
            resolvable: true,
            userId: tokenResults.user_id,
            visitorId: tokenResults.visitor_id
        })   
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
cache?.set(hashedClientToken, {
      anomalyType: 'Checks passed',
      canaryCookie: cookie,
      resolved: true,
      resolvable: false,
      userId: tokenResults.user_id,
      visitorId: tokenResults.visitor_id
})   
return {
  valid: true,
  reason: 'Checks passed',
  reqMFA: false
}

}


