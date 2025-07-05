import { ResultSetHeader } from "mysql2";
import { getPool } from "../config/dbConnection.js";
import { generateAccessToken } from "../../accsessTokens.js";
import { generateRefreshToken, IssuedRefreshToken } from "../../refreshTokens.js";
import { getConfiguration } from "../config/configuration.js";
import { getLogger } from "../utils/logger.js";

export async function findUserByProvider(provider: string, provider_id: string): Promise<{
    user: boolean;
    accessToken?: string;
    refreshToken?: IssuedRefreshToken;
}> {
    const log = getLogger().child({service: 'auth', branch: 'oauth'});
    const { jwt } = getConfiguration();
    const pool = await getPool()
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