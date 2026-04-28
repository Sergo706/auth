import mysql2 from 'mysql2/promise';
import { dbConfig } from '../configs/config.js';
import { toDigestHex } from '~~/utils/hashChecker.js';

export async function deleteApiToken(token: string) {
  const mainPool = await mysql2.createConnection(dbConfig);
  const { input: hash } = await toDigestHex(token);

  try {

    await mainPool.execute('DELETE FROM api_tokens WHERE api_token = ?', [hash]);

  } catch (err) {
    throw err;
  } finally {
    await mainPool.end();
  }

}