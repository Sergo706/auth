import mysql2 from 'mysql2/promise';
import { dbConfig } from '../configs/config.js';
import crypto from 'node:crypto';
import { toDigestHex } from '../../src/jwtAuth/utils/hashChecker.js';

export interface InsertedToken {
  raw: string;
  hash: string;
}

export async function insertRefreshToken(opts: {
  userId: number;
  ttlSeconds?: number;
  valid?: boolean;
  usageCount?: number;
}): Promise<InsertedToken> {
  const { userId, ttlSeconds = 900, valid = true, usageCount = 0 } = opts;
  const raw = crypto.randomBytes(64).toString('hex');
  const { input: hash } = await toDigestHex(raw);
  const conn = await mysql2.createConnection(dbConfig);
  try {
    await conn.execute(
      `INSERT INTO refresh_tokens (user_id, token, valid, expiresAt, usage_count, session_started_at)
       VALUES (?, ?, ?, DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND), ?, UTC_TIMESTAMP())`,
      [userId, hash, valid ? 1 : 0, ttlSeconds, usageCount]
    );
  } finally {
    await conn.end();
  }
  return { raw, hash };
}

export async function clearTokensForUser(userId: number): Promise<void> {
  const conn = await mysql2.createConnection(dbConfig);
  try {
    await conn.execute('DELETE FROM refresh_tokens WHERE user_id = ?', [userId]);
  } finally {
    await conn.end();
  }
}

export async function getTokenRow(hash: string): Promise<mysql2.RowDataPacket | null> {
  const conn = await mysql2.createConnection(dbConfig);
  try {
    const [rows] = await conn.execute<mysql2.RowDataPacket[]>(
      'SELECT * FROM refresh_tokens WHERE token = ?',
      [hash]
    );
    return rows[0] ?? null;
  } finally {
    await conn.end();
  }
}

export async function countValidTokensForUser(userId: number): Promise<number> {
  const conn = await mysql2.createConnection(dbConfig);
  try {
    const [rows] = await conn.execute<mysql2.RowDataPacket[]>(
      'SELECT COUNT(*) as count FROM refresh_tokens WHERE user_id = ? AND valid = 1',
      [userId]
    );
    return rows[0].count as number;
  } finally {
    await conn.end();
  }
}
