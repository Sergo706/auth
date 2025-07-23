import { ResultSetHeader } from "mysql2";
import { getPool } from "../config/dbConnection.js";
import { generateAccessToken } from "../../accessTokens.js";
import { generateRefreshToken, IssuedRefreshToken } from "../../refreshTokens.js";
import { getConfiguration } from "../config/configuration.js";
import { getLogger } from "../utils/logger.js";



/**
 * @description
 * Find a user by their OAuth provider details. If a matching user exists, returns `user: true`
 * along with newly issued tokens. Otherwise, `user` will be `false`.
 *
 * @param {string} provider - The name of the OAuth provider (e.g., `'github'`, `'google'`).
 * @param {string} provider_id - The unique ID of the user from the OAuth provider.
 *
 * @returns {Promise<{
 *   user: boolean;
 *   accessToken?: string;
 *   refreshToken?: IssuedRefreshToken;
 * }>}
 * Resolves with an object indicating whether the user was found, and if so, the issued tokens.
 *
 * @example
 * const result = await findUserByProvider('github', '987654321');
 * if (result.user) {
 *   // user was found, you can use result.accessToken and result.refreshToken
 * } else {
 *   // no user found for this provider
 * }
 *
 * @see {@link ./models/findUserByProvider.js}
 */
export async function findUserByProvider(provider: string, provider_id: string): Promise<{
    user: boolean;
    accessToken?: string;
    refreshToken?: IssuedRefreshToken;
}> {
    const log = getLogger().child({service: 'auth', branch: 'oauth'});
    const { jwt } = getConfiguration();
    const pool = getPool()
    try {
        const [findUser] = await pool.execute<ResultSetHeader[]>(`
            SELECT id, visitor_id FROM users
            WHERE provider = ?
            AND provider_id = ? 
            `,[provider, provider_id])

        if (!findUser || findUser.length === 0) {
            return {
                user: false,
            }
        }
   
        const {id, visitor_id} = findUser[0] as unknown as {
            id: number;
            visitor_id: number;
        };

        if (id && visitor_id) {
          const accessToken = generateAccessToken({id: id, visitor_id: visitor_id, jti: crypto.randomUUID()});
          const refresh = await generateRefreshToken(jwt.refresh_tokens.refresh_ttl,  id);
          return {
            user: true,
            accessToken: accessToken,
            refreshToken: refresh
          }
        }

    } catch(err) {
        log.error({err}, `Unexpected error finding a user's provider`);
    }

return {
    user: false
}
}