import { describe, it, expect, beforeAll, beforeEach, afterEach, inject, vi } from 'vitest';
import crypto from 'node:crypto';
import {
  consumeAndVerifyRefreshToken,
  generateRefreshToken,
  revokeRefreshToken,
} from '../../../src/refreshTokens.js';
import { toDigestHex } from '../../../src/jwtAuth/utils/hashChecker.js';
import { getPool } from '../../../src/jwtAuth/config/configuration.js';
import {
  clearTokensForUser,
  countValidTokensForUser,
  getTokenRow,
  insertRefreshToken,
} from '../../test-utils/refreshTokenHelper.js';

const TTL = 15 * 60 * 1000;

describe('consumeAndVerifyRefreshToken', () => {
  let testUserId: number;

  beforeAll(() => {
    testUserId = inject('testUserId');
  });

  beforeEach(async () => {
    await clearTokensForUser(testUserId);
  });

  it('should return valid:true with userId and visitor_id, and increment usage_count to 1', async () => {
    const { raw } = await generateRefreshToken(TTL, testUserId);
    const { input: hash } = await toDigestHex(raw);

    const result = await consumeAndVerifyRefreshToken(raw);

    expect(result.valid).toBe(true);
    expect(result.userId).toBe(testUserId);
    expect(typeof result.visitor_id).toBe('string');
    expect(result.sessionTTL).toBeInstanceOf(Date);

    const row = await getTokenRow(hash);
    expect(row!.usage_count).toBe(1);
  });

  it('should reject an unknown token with Token not found', async () => {
    const unknown = crypto.randomBytes(64).toString('hex');
    const result = await consumeAndVerifyRefreshToken(unknown);

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Token not found');
  });

  it('should reject a revoked token with Token has been revoked', async () => {
    const { raw } = await generateRefreshToken(TTL, testUserId);
    await revokeRefreshToken(raw);

    const result = await consumeAndVerifyRefreshToken(raw);

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Token has been revoked');
  });

  it('should revoke all user sessions and reject a token that was already consumed', async () => {
    const { raw } = await generateRefreshToken(TTL, testUserId);
    await generateRefreshToken(TTL, testUserId);
    await generateRefreshToken(TTL, testUserId);

    await consumeAndVerifyRefreshToken(raw); 
    const result = await consumeAndVerifyRefreshToken(raw);

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Token already used, Please login again');
    expect(await countValidTokensForUser(testUserId)).toBe(0);
  });

  it('should reject an expired token with Invalid token', async () => {
    const { raw } = await insertRefreshToken({ userId: testUserId, ttlSeconds: -1 });

    const result = await consumeAndVerifyRefreshToken(raw);

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Invalid token');
  });
});

describe('consumeAndVerifyRefreshToken success path', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  function mockPoolConnection(executeResponses: unknown[][]) {
    let callIndex = 0;
    const mockConn = {
      beginTransaction: vi.fn().mockResolvedValue(undefined),
      execute: vi.fn().mockImplementation(() =>
        Promise.resolve(executeResponses[callIndex++])
      ),
      commit: vi.fn().mockResolvedValue(undefined),
      rollback: vi.fn().mockResolvedValue(undefined),
      release: vi.fn(),
    };
    vi.spyOn(getPool(), 'getConnection').mockResolvedValueOnce(mockConn as any);
    return mockConn;
  }

  it('should rollback and return Token not found when post UPDATE SELECT returns empty rows', async () => {
    const mockConn = mockPoolConnection([
      [{ affectedRows: 1 }],
      [[]],
    ]);

    const result = await consumeAndVerifyRefreshToken(crypto.randomBytes(64).toString('hex'));

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Token not found');
    expect(mockConn.rollback).toHaveBeenCalledOnce();
    expect(mockConn.commit).not.toHaveBeenCalled();
  });

  it('should delete the token and return Token has been revoked when post UPDATE SELECT shows valid=0', async () => {
    const mockConn = mockPoolConnection([
      [{ affectedRows: 1 }],
      [[{        
        user_id: 1,
        valid: 0,
        expiresAt: new Date(Date.now() + 900_000),
        session_started_at: new Date(),
        visitor_id: 'visitor-uuid',
      }]],
      [{ affectedRows: 1 }], // DELETE
    ]);

    const result = await consumeAndVerifyRefreshToken(crypto.randomBytes(64).toString('hex'));

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Token has been revoked');
    expect(mockConn.commit).toHaveBeenCalledOnce();

    const deleteSql = mockConn.execute.mock.calls[2][0] as string;
    expect(deleteSql).toContain('DELETE');
  });

  it('should mark token invalid and return Token expired when JS clock finds expiresAt in the past', async () => {
    const mockConn = mockPoolConnection([
      [{ affectedRows: 1 }], 
      [[{                     
        user_id: 1,
        valid: 1,
        expiresAt: new Date(Date.now() - 1000),
        session_started_at: new Date(),
        visitor_id: 'visitor-uuid',
      }]],
      [{ affectedRows: 1 }],                         // UPDATE: set valid=0, last_mfa_at=NULL
    ]);

    const result = await consumeAndVerifyRefreshToken(crypto.randomBytes(64).toString('hex'));

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Token expired');
    expect(result.userId).toBe(1);
    expect(mockConn.commit).toHaveBeenCalledOnce();
  });
});
