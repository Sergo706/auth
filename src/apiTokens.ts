import { getLogger } from "./jwtAuth/utils/logger.js";
import crypto, { createHash } from 'crypto'
import { getConfiguration, getPool } from "./jwtAuth/config/configuration.js";
import { ResultSetHeader, RowDataPacket } from 'mysql2';
import { ensureSha256Hex, toDigestHex } from "./jwtAuth/utils/hashChecker.js";
import { Results } from "@riavzon/utils";
import type { ActionArgs, ActionManagerResult, AllValidTokensList, CreationSuccess, RotationSuccess, Row, SingleTokenMeta, VerifySuccessResponse } from "~~/types/Api.js";
import pino from "pino";


/**
 * Generates a short SHA-256 checksum from a provided string.
 * @param data - The raw string to hash.
 * @returns An 8-character hexadecimal checksum.
 */
export function generateChecksum(data: string): string {
    return createHash('sha256').update(data).digest('hex').substring(0, 8);
}

/**
 * Performs a timing-safe comparison of two hexadecimal strings.
 * @param a - The first hex string.
 * @param b - The second hex string.
 * @returns True if the strings are identical and of equal length.
 */
export function isSame(a: string, b: string) {
  const A = Buffer.from(a, "hex");
  const B = Buffer.from(b, "hex");
  if (A.length !== B.length) return false;
  return crypto.timingSafeEqual(A, B);
}

/**
 * Validates the integrity of a public identifier by verifying its embedded checksum.
 * @param publicIdentifier - The composite string consisting of [randomPart]_[checksum].
 * @param log - Pino logger instance for reporting validation failures.
 * @returns True if the checksum matches the random component.
 */
export function validateChecksumPublicIdent(publicIdentifier: string, log: pino.Logger) {
    const [providedRandomPart, providedChecksum] = publicIdentifier.split('_')

    if (!providedRandomPart || !providedChecksum) {
        log.info('Invalid public identifier is used. missing randomPart or checksum')
        return false;
    }

    const calculatedChecksum = generateChecksum(providedRandomPart);

    if (!isSame(providedChecksum, calculatedChecksum)) {
        log.info('Invalid public identifier checksum provided')
        return false;
    }  

    return true;
}

/**
 * Retrieves a summary of token counts (valid, invalid, and total) for a specific user.
 * @param userId - The unique identifier of the user.
 * @returns An object containing the counts for each token state.
 * @throws Database execution errors.
 */
export async function totalUserTokensCount(userId: number) {
    const pool = getPool()

    try {
       const [rows] = await pool.execute<RowDataPacket[]>(`
            SELECT 
                COUNT(CASE WHEN valid = 1 THEN 1 END) AS totalValidTokens,
                COUNT(CASE WHEN valid = 0 THEN 1 END) AS totalInvalidTokens,
                COUNT(*) AS total
            FROM api_tokens
            WHERE user_id = ?
            `,[userId])
        if (!rows || rows.length === 0) {
            return {
                totalValidTokens: 0,
                totalInvalidTokens: 0,
                total: 0
            }
        }
        const row = rows[0] 
        return {
            userId,
            totalValidTokens: Number(row.totalValidTokens) || 0,
            totalInvalidTokens: Number(row.totalInvalidTokens) || 0,
            total: Number(row.total) || 0
        }
    } catch (err) {
        throw err;
    }
}

// Dashboard, public

/**
 * Generates and stores a new API key and a corresponding public identifier.
 * Validates user token limits before generation.
 * @param userId - The owner of the new key.
 * @param privilegeType - The access level assigned to the token.
 * @param name - A friendly name for identifying the token in the dashboard.
 * @param prefix - The string prefix for the raw API key (defaults to 'api').
 * @param expires - Optional TTL in milliseconds.
 * @param ipAddresses - Optional array of authorized IPv4/IPv6 addresses.
 * @returns A result object containing the data `rawApiKey`, `rawPublicId`, and `expiresAt`.
 */
export async function createApiKey(
    userId: number, 
    privilegeType: 'demo' | 'restricted' | 'protected' | 'full' | 'custom',
    name: string,
    prefix: string = 'api',
    expires?: number,
    ipAddresses?: string[]
): Promise<Results<CreationSuccess>> {
    const log = getLogger().child({service: 'auth', branch: 'api_tokens', type: 'create', date: new Date().toISOString()});
    log.info({userId}, 'Generating api key for user')
    const { userId: userIdFromCount, totalInvalidTokens, totalValidTokens, total } = await totalUserTokensCount(userId);
    const { apiTokens } = getConfiguration()
    if (totalValidTokens >= apiTokens.limitTokensPerUser) {
        log.warn({userId, limit: apiTokens.limitTokensPerUser }, 'User exceeded maximum limit of allowed tokens')
        return {
            ok: false,
            date: new Date().toISOString(),
            reason: `You cannot have more then ${apiTokens.limitTokensPerUser} valid tokens at a time`
        }
    } 

    log.info({userIdFromCount, totalInvalidTokens, totalValidTokens, total}, 'User tokens count')
    const randomPart = crypto.randomBytes(64).toString('hex');
    const expiresAt = expires ? new Date(Date.now() + expires) : null;
    const checksum = generateChecksum(randomPart);
    const rawApiKey = `${prefix}_${randomPart}_${checksum}`;

    // public_identifier, should not be hashed.
    const randomPublic = crypto.randomBytes(64).toString('hex');
    const rawPublicId = `${randomPublic}_${generateChecksum(randomPublic)}`; 

    try {
        const { input: hash } = await toDigestHex(rawApiKey)

        const pool = getPool();

        const stm = `
            INSERT INTO api_tokens
              (name, public_identifier, prefix, user_id, api_token, created_at, expires_at, last_used, privilege_type, usage_count, valid, restricted_to_ip_address)
            VALUES (
                ?,
                ?,
                ?,
                ?,
                ?,
                UTC_TIMESTAMP(),
                ${expires ? "DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND)" : "NULL"},
                UTC_TIMESTAMP(),
                ?,
                0,
                ?,
                ?
                )
        `;
        const restrictedToIp = ipAddresses ? JSON.stringify(ipAddresses) : null;
        const params = [
            name,
            rawPublicId,
            prefix,
            userId,
            hash,
            ...(expires ? [Math.floor(expires / 1000)] : []),
            privilegeType,
            true,
            restrictedToIp
        ]

        await pool.execute<ResultSetHeader>(stm, params)
        log.info({userId}, 'Successfully generated new api key')
      
    } catch (err) {
        log.error({err},'Error generating Api key')
        throw new Error('DB error generating Api key');
    }

    return {
        ok: true,
        date: new Date().toISOString(),
        data: {
            rawApiKey,
            rawPublicId,
            expiresAt
        }
    }
}

// M2M, public

/**
 * The primary M2M verification logic. Validates raw keys against hashed database records.
 * Handles checksum verification, IP restrictions, privilege checks, and expiration logic.
 * @param rawKey - The raw API key string can be hashed or raw.
 * @param skipCountUpdates - If true, usage counters and 'last_used' timestamps are not updated.
 * @param providedPrivilege - The privilege level required for the current request.
 * @param byPassIpCheck - If true, IP restriction validation is skipped.
 * @param isInternalHash - Set to true if the input is already a hash/internal value to skip checksum splitting.
 * @param ipAddress - The source IP of the request for restriction validation.
 * @returns A result object containing token metadata if authorized.
 */
export async function verifyApiKey(
    rawKey: string,
    skipCountUpdates: boolean,
    providedPrivilege:  'demo' | 'restricted' | 'protected' | 'full' | 'custom',
    byPassIpCheck: boolean,
    isInternalHash: boolean = false,
    ipAddress?: string
): Promise<Results<VerifySuccessResponse>> {
    const log = getLogger().child({service: 'auth', branch: 'api_tokens', type: 'verify', date: new Date().toISOString()});

    // is it called by an internal helpers? is it already hashed? if so skip checksum and rawKey.split('_')
    if (!isInternalHash) {
        const [prefix, providedRandomPart, providedChecksum] = rawKey.split('_')

        // reject noise fast
        if (!prefix || !providedRandomPart || !providedChecksum) {
            log.info('Invalid api key is used. Missing prefix, randomPart or checksum')
            return {
                ok: false,
                date: new Date().toISOString(),
                reason: 'Invalid key'
            }
        }

        const calculatedChecksum = generateChecksum(providedRandomPart);

        if (!isSame(providedChecksum, calculatedChecksum)) {
            log.info('Invalid api key checksum provided')
            return {
                ok: false,
                date: new Date().toISOString(),
                reason: 'Invalid key'
            }
        }   
 }

    // ensure it hashed, even if already was, toDigestHex will not hash again
    const { input: token } = await toDigestHex(rawKey);  
    const hashedApiToken = ensureSha256Hex(token);    

    const pool = getPool();
    const conn = await pool.getConnection();
    let stm = `
         SELECT 
              api_tokens.id,
              api_tokens.name,
              api_tokens.user_id,
              api_tokens.api_token,
              api_tokens.created_at,
              api_tokens.expires_at,
              api_tokens.restricted_to_ip_address,
              api_tokens.last_used,
              api_tokens.usage_count,
              users.visitor_id  
        FROM api_tokens
                JOIN users ON api_tokens.user_id = users.id 
        WHERE api_tokens.api_token = ?
                AND api_tokens.valid = 1
                AND api_tokens.privilege_type = ?
         LIMIT 1
    `;
    if (!skipCountUpdates) stm += ` FOR UPDATE`;
    
    try {
        await conn.beginTransaction();  
        const [rows] = await conn.execute<RowDataPacket[]>(stm, [hashedApiToken, providedPrivilege])


       // Token doesnt exists in the db, haves insufficient privileges, or is marked as invalid already.
        if (!rows || rows.length === 0) {
            log.info('This api token is invalid. invalid token or insufficient privileges')
            await conn.rollback();
            return {
                ok: false,
                date: new Date().toISOString(),
                reason: 'Invalid key'
            }
        }
     
     const row = rows[0];
     //  does the caller/controller wants validation?
     if (!byPassIpCheck) {
            // is the restriction configured by a consumer in the db? 
        if (row.restricted_to_ip_address) {
            // the consumer configured an host restrictions, but didnt provided an ip, reject it
            if (!ipAddress) {
                log.warn({userId: row.user_id}, 'User send a req without the configured ip address')
                await conn.rollback();
                return {
                    ok: false,
                    date: new Date().toISOString(),
                    reason: 'Invalid Host'
                }
            }
            
                const allowedIps = JSON.parse(row.restricted_to_ip_address) as string[];
                if (!allowedIps.includes(ipAddress)) {
                    log.warn({userId: row.user_id}, 'User send a req from unauthorized host')
                    await conn.rollback();
                    return {
                        ok: false,
                        date: new Date().toISOString(),
                        reason: 'Invalid Host'
                    }
                }
        }
     }

      // Is expired?
      const expiryTime = row.expires_at ? row.expires_at.getTime() : null;

     if (expiryTime && expiryTime < Date.now()) {
        // Invalided it
            await conn.execute(`
                UPDATE api_tokens
                 SET 
                 api_tokens.valid = 0
                 WHERE api_tokens.api_token = ? 
                 AND api_tokens.valid = 1 
                 `, [hashedApiToken]);
                 await conn.commit();
                 
            log.warn({userId: row.user_id}, 'Token expired, and was invalided')
            return {
                ok: false,
                date: new Date().toISOString(),
                reason: "Token expired",
            }
     }

     // Update new data or skip for internal stuff
     if (!skipCountUpdates) {
        await conn.execute(`
            UPDATE api_tokens
             SET
                api_tokens.usage_count = api_tokens.usage_count + 1,
                api_tokens.last_used = UTC_TIMESTAMP()
            WHERE api_tokens.id = ?
            AND api_tokens.api_token = ?
            AND api_tokens.valid = 1
            AND api_tokens.user_id = ?   
            `, [row.id, hashedApiToken, row.user_id])
        }

        await conn.commit();
    // Give callers data to make rate limits and custom business logic, etc..
    return {
        ok: true,
        date: new Date().toISOString(),
        data: {
            name: row.name,
            tokenId: row.id,
            userId: row.user_id,
            createdAt: row.created_at,
            expiresAt: row.expires_at,
            lastUsed: !skipCountUpdates ? new Date().toISOString() : row.last_used,
            usageCount: !skipCountUpdates ? row.usage_count + 1 : row.usage_count,
            providedPrivilege // Validated already
        }
    }
    } catch (err: unknown) {
        await conn.rollback();
        log.error({err}, 'Error validating token')
        return {
            ok: false,
            date: new Date().toISOString(),
            reason: 'Server error validating token.'
        }
    } finally {
        conn.release();
    }

}

//DashBoard private
/**
 * Permanently invalidates an API key.
 * @param rawKey - The key to be revoked, can be hashed or raw.
 * @param providedPrivilege - The privilege type associated with the key.
 * @returns A standard result object confirming revocation.
 */
export async function revokeApiKey
(
    rawKey: string,
    providedPrivilege:  'demo' | 'restricted' | 'protected' | 'full' | 'custom',
): Promise<Results<{msg: string, invalidedTokenId: number, userId: number} | string>> {
    const log = getLogger().child({service: 'auth', branch: 'api_tokens', type: 'revoke', date: new Date().toISOString()});
    const { input: token } = await toDigestHex(rawKey);  
    const hashedApiToken = ensureSha256Hex(token);    
    const pool = getPool();

    try {
        // called from the manager skip raw check, counters and security checks
        const verifyRes = await verifyApiKey(rawKey, true, providedPrivilege, true, true, undefined)
        if (!verifyRes.ok) {
            log.warn({reason: verifyRes.reason}, 'User tried invalidating invalid token');
            return {
                ok: true,
                date: verifyRes.date,
                data: 'Token invalided successfully'
            }
        }

   const [updated] = await pool.execute<ResultSetHeader>(`
        UPDATE api_tokens 
         SET valid = 0
        WHERE id = ?
         AND user_id = ?
         AND api_token = ?
        `, [verifyRes.data?.tokenId, verifyRes.data?.userId, hashedApiToken])

    if (updated.affectedRows === 0) {
         log.warn({data: verifyRes.data, updated}, '0 affected rows, token is not invalided. user, or token didnt found');
         return {
            ok: false,
            date: new Date().toISOString(),
            reason: 'Token invalided successfully'
        }
    }    

    log.info({data: verifyRes.data}, 'User invalidated his token');
    return {
        ok: true,
        date: verifyRes.date,
        data: {
            msg: 'Token invalided successfully',
            invalidedTokenId: verifyRes.data?.tokenId,
            userId: verifyRes.data?.userId
        }
    }

    } catch (err) {
        log.error({err}, 'Error invalidating token');
        return {
            ok: false,
            date: new Date().toISOString(),
            reason: 'Error invalidating token'
        }
    }

}

// DashBoard private

/**
 * Rotates an existing API key by revoking the old one and creating a new one with identical attributes.
 * Useful for security refreshes or leaked key mitigation.
 * @param rawOldToken - The current valid key to rotate can be hashed or raw.
 * @param privilegeType - The privilege level of the key.
 * @param name - The name of the token.
 * @param deleteOnRotation - If true, the old record is deleted from the DB instead of just being marked invalid.
 * @param ipAddress - Inherited or new IP restrictions.
 * @param expires - Inherited or new TTL.
 * @param prefix - Prefix for the new key.
 * @returns The new raw API key and its metadata.
 */
export async function rotateApiKey(
    rawOldToken: string,
    privilegeType:  'demo' | 'restricted' | 'protected' | 'full' | 'custom',
    name: string,
    deleteOnRotation = false,
    ipAddress?: string[],
    expires?: number,
    prefix = 'api'
): Promise<Results<RotationSuccess>> {
    const log = getLogger().child({service: 'auth', branch: 'api_tokens', type: 'rotate', date: new Date().toISOString()});
    const pool = getPool();
   
   try {

    const revokeResults = await revokeApiKey(rawOldToken, privilegeType);

    if (!revokeResults.ok) {
        log.warn({reason: revokeResults.reason}, 'This token cant be rotated. because it cant be revoked');
        return {
            ok: false,
            date: revokeResults.date,
            reason: 'Token cannot be rotated this time'
        }
    }
  
   if (typeof revokeResults.data === 'string') {
        log.warn({...revokeResults}, 'User tried to rotate revoked token')
        return {
            ok: false,
            date: new Date().toISOString(),
            reason: 'Cannot rotate revoked token'
        }
   }
   // maybe delete
  if (deleteOnRotation) {
   const [deleted] = await pool.execute<ResultSetHeader>(`
        DELETE FROM api_tokens 
         WHERE id = ?
         AND user_id = ?
         AND valid = 0
        LIMIT 1
    `,[revokeResults.data.invalidedTokenId, revokeResults.data.userId])

   if (deleted.affectedRows === 0) {
        log.warn('This token cant be rotated. because it cant be deleted first');
        return {
            ok: false,
            date: revokeResults.date,
            reason: 'Token cannot be rotated this time'
        }
   }
  }
    // new
    const newCreatedToken = await createApiKey(revokeResults.data.userId, privilegeType, name, prefix, expires, ipAddress)   

    log.info({userId: revokeResults.data.userId}, 'User successfully rotated a token');

    if (!newCreatedToken.ok) {
        log.warn({...newCreatedToken}, 'Cant create new tokens in this rotation')
        return {
            ok: false,
            date: revokeResults.date,
            reason: newCreatedToken.reason ?? 'Cant create new tokens in this rotation'
        }
    }

    return {
        ok: true, 
        date: revokeResults.date,
        data: {
            msg: 'Successfully rotated an api key',
            newRawToken:  newCreatedToken.data.rawApiKey,
            newExpiry:  newCreatedToken.data.expiresAt ?? null
        }
    }
   } catch (err) {
        log.info({err}, 'Error rotating token');
        return {
            ok: false, 
            date: new Date().toISOString(),
            reason: 'Server error rotating a token.'
        }
   }
}

// DashBoard private
/**
 * Retrieves metadata and user-wide token counts for a specific API key.
 * @param rawApiKey - The key to query can be hashed or raw.
 * @param providedPrivilege - The privilege level for verification.
 * @returns Token metadata and global user token statistics.
 */
export async function getUserApiKeysMetaData(
    rawApiKey: string,
    providedPrivilege:  'demo' | 'restricted' | 'protected' | 'full' | 'custom',
): Promise<Results<SingleTokenMeta>> {
    const log = getLogger().child({service: 'auth', branch: 'api_tokens', type: 'metadata', date: new Date().toISOString()});

    try {
        // called from the manager skip raw check, counters and security checks
        const verifyRes = await verifyApiKey(rawApiKey, true, providedPrivilege, true, true, undefined)
        if (!verifyRes.ok) {
            log.info({reason: verifyRes.reason}, 'Cant get metadata about invalid token');
            return {
                ok: false,
                date: verifyRes.date,
                reason: verifyRes.reason ?? 'Cant get metadata about invalid token'
            }
        }
        const { totalInvalidTokens, totalValidTokens, total } = await totalUserTokensCount(verifyRes.data.userId);
        return {
            ok: true,
            date: verifyRes.date,
            data: {
                tokenMeta: { ...verifyRes.data },
                counts: { totalInvalidTokens, totalValidTokens, total }
            }
        }
    } catch (err) {
        log.error({err}, 'Error getting metadata');
        return {
            ok: false,
            date: new Date().toISOString(),
            reason: 'Error getting metadata'
        }
    }
}


//Dashboard private

/**
 * Updates the IP address whitelist for an existing token.
 * @param userId - The ID of the user performing the update.
 * @param rawToken - The token to update can be hashed or raw.
 * @param newIpAddress - Array of strings or null to remove restrictions.
 * @returns A success message or error reason.
 */
export async function updateRestriction(
    userId: number,
    rawToken: string,
    newIpAddress: string[] | null,
): Promise<Results<{ msg: string }>> {
    const log = getLogger().child({ service: 'auth', branch: 'api_tokens', type: 'update_ip' });
    const pool = getPool();
    const { input: token } = await toDigestHex(rawToken)
    const hashedApiToken = ensureSha256Hex(token);
    const dbValue = (newIpAddress && newIpAddress.length > 0) ? JSON.stringify(newIpAddress) : null;

    try {
        const [result] = await pool.execute<ResultSetHeader>(`
            UPDATE api_tokens
            SET 
              restricted_to_ip_address = ?
            WHERE 
                api_token = ? 
            AND user_id = ?
        `, [
             dbValue,
             hashedApiToken, 
             userId
            ]);

        if (result.affectedRows === 0) {
            return {
                ok: false,
                date: new Date().toISOString(),
                reason: 'Token not found or unauthorized'
            };
        }

        log.info({ userId, newIpAddress }, 'IP restriction updated');
        return {
            ok: true,
            date: new Date().toISOString(),
            data: { msg: 'Restriction updated successfully' }
        };
    } catch (err) {
        log.error({ err }, 'Error updating IP restriction');
        return {
            ok: false,
            date: new Date().toISOString(),
            reason: 'Internal server error'
        };
    }
}

// Plan/Priv updates etc... private

/**
 * Updates the privilege level/access tier of an existing token.
 * @param userId - The ID of the user performing the update.
 * @param rawToken - The token to update can be hashed or raw.
 * @param newPrivileges - The new access tier to assign.
 */
export async function updatePrivileges(
    userId: number,
    rawToken: string,
    newPrivileges: 'demo' | 'restricted' | 'protected' | 'full' | 'custom',
): Promise<Results<{ msg: string }>> {

    const log = getLogger().child({ service: 'auth', branch: 'api_tokens', type: 'update_privileges' });
    const pool = getPool();
    const { input: token } = await toDigestHex(rawToken)
    const hashedApiToken = ensureSha256Hex(token);

    try {
        const [result] = await pool.execute<ResultSetHeader>(`
            UPDATE api_tokens
            SET 
              privilege_type = ?
            WHERE 
                api_token = ? 
            AND user_id = ?
        `, [
             newPrivileges,
             hashedApiToken, 
             userId
            ]);

        if (result.affectedRows === 0) {
            return {
                ok: false,
                date: new Date().toISOString(),
                reason: 'Token not found or unauthorized'
            };
        }

        log.info({ userId, newPrivileges }, 'Privileges updated');
        return {
            ok: true,
            date: new Date().toISOString(),
            data: { msg: 'Privileges updated successfully' }
        };
    } catch (err) {
        log.error({ err }, 'Error updating Privileges');
        return {
            ok: false,
            date: new Date().toISOString(),
            reason: 'Internal server error'
        };
    }
}


// Dashboard, public.

/**
 * Retrieves a list of all currently valid tokens for a user.
 * Redacts raw keys but includes public identifiers for management actions.
 * @param userId - The user whose tokens are being queried.
 * @returns A list of token metadata and usage counts.
 */
export async function getAllValidTokensList(userId: number): Promise<Results<AllValidTokensList>>{
    const log = getLogger().child({ service: 'auth', branch: 'api_tokens', type: 'get_list_meta' });
    const pool = getPool();
    
    try {
        const { totalInvalidTokens, totalValidTokens, total } = await totalUserTokensCount(userId);
        // let authenticated callers get meta data, and the raw publicId to be able to perform actions
        const [rows] = await pool.execute<RowDataPacket[]>(`
            SELECT 
              api_tokens.id,
              api_tokens.name,
              api_tokens.created_at,
              api_tokens.expires_at,
              api_tokens.restricted_to_ip_address,
              api_tokens.last_used,
              api_tokens.usage_count,
              api_tokens.public_identifier,
              api_tokens.privilege_type
            FROM api_tokens 
            WHERE user_id = ?
            AND valid = 1
            `, [userId])

        const dataToSend: AllValidTokensList = {
            total,
            totalInvalidTokens,
            totalValidTokens
        }

        if (rows && rows.length > 0) {
            const mapped = rows.map((list) => ({
                ...list, 
                restricted_to_ip_address: JSON.parse(list.restricted_to_ip_address)
            }));
            Object.assign(dataToSend, { tokenList: mapped })
        };

        log.info({ userId, dataToSend }, 'Sending tokens metadata');

        return {
            ok: true,
            date: new Date().toISOString(),
            data: dataToSend
        }
        
    } catch(err) {
        log.error({err}, `Error sending metadata list`)
        return {
            ok: false,
            date: new Date().toISOString(),
            reason: 'Server error'
        }
    }
}


// dashboard public

/**
 * High-level coordinator for dashboard-driven token actions.
 * Uses the public identifier to find the corresponding hashed token and execute requested logic.
 * @param userId - The ID of the authenticated user.
 * @param tokenId - The internal database ID of the token.
 * @param publicIdentifier - The non-sensitive identifier used as a proxy for the raw key.
 * @param name - The name of the token for verification.
 * @param options - Arguments defining the action (revoke, rotate, metadata, etc.), and the associated payload for an action.
 * @returns The result of the specific sub-action performed.
 */
export async function privateActionManager(
    userId: number,
    tokenId: number,
    publicIdentifier: string,
    name: string,
    options: ActionArgs,
): Promise<ActionManagerResult> {

    const log = getLogger().child({ service: 'auth', branch: 'api_tokens', type: 'action_manager', date: new Date().toISOString() });
    const pool = getPool();

    try {
        // validate public identity checksum
        const isValidChecksum = validateChecksumPublicIdent(publicIdentifier, log);
        if (!isValidChecksum) {
            return {
                ok: false,
                date: new Date().toISOString(),
                reason: 'Invalid identity'
            }
        }

        // check if this publicId exists along side other attr
        const [rows] = await pool.execute<RowDataPacket[]>(
            `SELECT * FROM api_tokens 
             WHERE id = ? 
              AND user_id = ? 
              AND name = ?
              AND public_identifier = ?
              AND valid = 1
             LIMIT 1`,
            [tokenId, userId, name, publicIdentifier]
        );

        if (!rows || rows.length === 0) {
            log.info({ userId, tokenId, action: options.action }, "user doesn't have access to this token")
            return {
                ok: false,
                date: new Date().toISOString(),
                reason: 'Bad Request'
            }
        }

        const userToken = rows[0] as Row;
        
        switch(options.action) {
            case 'revoke': 
                return await revokeApiKey(userToken.api_token, userToken.privilege_type);

            case 'rotate':
                // create new with the exact same attributes callers needs to make completely new one, or call the update functions to change these
                let ips: string[] | undefined;
                let remainingTtl: number | undefined;

                if (userToken.restricted_to_ip_address) ips = JSON.parse(userToken.restricted_to_ip_address) as string[];

                if (userToken.expires_at) {
                    const expiryDate = new Date(userToken.expires_at).getTime();
                    remainingTtl = Math.max(0, expiryDate - Date.now()); 
                }
                
                return await rotateApiKey(userToken.api_token, userToken.privilege_type, userToken.name, false, ips, remainingTtl, userToken.prefix);

            case 'metadata':
                return await getUserApiKeysMetaData(userToken.api_token, userToken.privilege_type);

            case 'ip-restriction-update': 
                 const newIps = options.newIpAddress
                 return await updateRestriction(userId, userToken.api_token, newIps);

            case 'privilege-update': 
                return await updatePrivileges(userId, userToken.api_token, options.newPrivileges as "custom" | "demo" | "restricted" | "protected" | "full")

            default:
                // @ts-ignore
                log.info({ userId, tokenId, action: options.action }, 'Invalid action provided.')
                return {
                    ok: false,
                    date: new Date().toISOString(),
                    reason: 'Bad Request'
                }
        }
    } catch (err) {
        return {
            ok: false,
            date: new Date().toISOString(),
            reason: 'Server Error'
        }
    }
}  
