import mysql2, { RowDataPacket } from 'mysql2/promise';
import { dbConfig } from '../configs/config.js';
import { toDigestHex } from '~~/utils/hashChecker.js';
import { Row } from '~~/types/Api.js';

export async function getToken(token: string) {
    const mainPool = await mysql2.createConnection(dbConfig);
  
    try {

        const {input: hash} = await toDigestHex(token)
        const [rows] = await mainPool.execute<RowDataPacket[]>(`SELECT * FROM api_tokens WHERE api_token = ?`, [hash])
        const row = rows[0] as Row
        return row
    } catch (err) {
        throw err
    } finally { await mainPool.end(); }
}