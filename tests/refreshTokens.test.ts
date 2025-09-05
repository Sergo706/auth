import { expect, test, describe, beforeEach, vi, afterEach } from 'vitest'
import { 
    generateRefreshToken, 
    verifyRefreshToken, 
    consumeAndVerifyRefreshToken,
    rotateRefreshToken,
    revokeRefreshToken,
    IssuedRefreshToken
} from '../src/refreshTokens.js';
import crypto from 'node:crypto'

// Mock database connection and results
const mockConnection = {
    execute: vi.fn(),
    beginTransaction: vi.fn(),
    commit: vi.fn(),
    rollback: vi.fn(),
    release: vi.fn()
};

const mockPool = {
    execute: vi.fn(),
    getConnection: vi.fn(() => Promise.resolve(mockConnection))
};

// Mock dependencies
vi.mock('../src/jwtAuth/config/dbConnection.js', () => ({
    getPool: vi.fn(() => mockPool)
}));

vi.mock('../src/jwtAuth/utils/logger.js', () => ({
    getLogger: vi.fn(() => ({
        child: vi.fn(() => ({
            info: vi.fn(),
            warn: vi.fn(),
            error: vi.fn()
        }))
    }))
}));

describe('Refresh Token Functions', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        // Reset mock implementations
        mockConnection.execute.mockResolvedValue([{ insertId: 1, affectedRows: 1 }]);
        mockConnection.beginTransaction.mockResolvedValue(undefined);
        mockConnection.commit.mockResolvedValue(undefined);
        mockConnection.rollback.mockResolvedValue(undefined);
        mockConnection.release.mockResolvedValue(undefined);
        mockPool.execute.mockResolvedValue([{ affectedRows: 1 }]);
    });

    afterEach(() => {
        vi.clearAllMocks();
    });

    describe('generateRefreshToken', () => {
        test('should generate a valid refresh token with correct structure', async () => {
            const ttl = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds
            const userId = 123;

            const result = await generateRefreshToken(ttl, userId);

            // Verify structure
            expect(result).toHaveProperty('raw');
            expect(result).toHaveProperty('hashedToken');
            expect(result).toHaveProperty('expiresAt');

            // Verify token properties
            expect(result.raw).toMatch(/^[a-f0-9]{128}$/); // 64 bytes = 128 hex chars
            expect(result.hashedToken).toMatch(/^[a-f0-9]{64}$/); // SHA256 = 64 hex chars
            expect(result.expiresAt).toBeInstanceOf(Date);

            // Verify expiration time is approximately correct
            const expectedExpiry = new Date(Date.now() + ttl);
            const timeDiff = Math.abs(result.expiresAt.getTime() - expectedExpiry.getTime());
            expect(timeDiff).toBeLessThan(1000); // Within 1 second

            // Verify database call
            expect(mockPool.execute).toHaveBeenCalledWith(
                expect.stringContaining('INSERT INTO refresh_tokens'),
                [userId, result.hashedToken, true, result.expiresAt]
            );
        });

        test('should generate unique tokens for multiple calls', async () => {
            const ttl = 7 * 24 * 60 * 60 * 1000;
            const userId = 123;

            const result1 = await generateRefreshToken(ttl, userId);
            const result2 = await generateRefreshToken(ttl, userId);

            expect(result1.raw).not.toBe(result2.raw);
            expect(result1.hashedToken).not.toBe(result2.hashedToken);
        });

        test('should handle database errors gracefully', async () => {
            const ttl = 7 * 24 * 60 * 60 * 1000;
            const userId = 123;

            mockPool.execute.mockRejectedValue(new Error('Database connection failed'));

            await expect(generateRefreshToken(ttl, userId)).rejects.toThrow('DB error generating refresh token');
        });

        test('should verify token hash is correct', async () => {
            const ttl = 7 * 24 * 60 * 60 * 1000;
            const userId = 123;

            const result = await generateRefreshToken(ttl, userId);

            // Manually hash the raw token and compare
            const expectedHash = crypto.createHash('sha256').update(result.raw).digest('hex');
            expect(result.hashedToken).toBe(expectedHash);
        });
    });

    describe('verifyRefreshToken', () => {
        test('should verify valid refresh token successfully', async () => {
            const rawToken = crypto.randomBytes(64).toString('hex');
            const hashedToken = crypto.createHash('sha256').update(rawToken).digest('hex');
            const mockResults = [{
                user_id: 123,
                visitor_id: 456,
                valid: true,
                expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 1 day from now
                session_started_at: new Date()
            }];

            mockPool.execute
                .mockResolvedValueOnce([{ affectedRows: 1 }]) // UPDATE usage_count
                .mockResolvedValueOnce([mockResults]); // SELECT query

            const result = await verifyRefreshToken(rawToken, false);

            expect(result.valid).toBe(true);
            expect(result.userId).toBe(123);
            expect(result.visitor_id).toBe(456);
            expect(result.sessionTTL).toBeInstanceOf(Date);
            expect(result.reason).toBeUndefined();

            // Verify token was hashed for database query
            expect(mockPool.execute).toHaveBeenCalledWith(
                expect.stringContaining('UPDATE refresh_tokens'),
                [hashedToken]
            );
        });

        test('should verify pre-hashed token when hashed flag is true', async () => {
            const hashedToken = crypto.randomBytes(32).toString('hex');
            const mockResults = [{
                user_id: 123,
                visitor_id: 456,
                valid: true,
                expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
                session_started_at: new Date()
            }];

            mockPool.execute
                .mockResolvedValueOnce([{ affectedRows: 1 }])
                .mockResolvedValueOnce([mockResults]);

            const result = await verifyRefreshToken(hashedToken, true);

            expect(result.valid).toBe(true);
            
            // Should use the token directly without hashing
            expect(mockPool.execute).toHaveBeenCalledWith(
                expect.stringContaining('UPDATE refresh_tokens'),
                [hashedToken]
            );
        });

        test('should return invalid for non-existent token', async () => {
            const rawToken = crypto.randomBytes(64).toString('hex');

            mockPool.execute
                .mockResolvedValueOnce([{ affectedRows: 1 }])
                .mockResolvedValueOnce([[]]); // Empty result set

            const result = await verifyRefreshToken(rawToken, false);

            expect(result.valid).toBe(false);
            expect(result.reason).toBe('Token not found');
            expect(result.userId).toBeUndefined();
        });

        test('should handle revoked tokens and delete them', async () => {
            const rawToken = crypto.randomBytes(64).toString('hex');
            const mockResults = [{
                user_id: 123,
                visitor_id: 456,
                valid: false, // Token is revoked
                expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
                session_started_at: new Date()
            }];

            mockPool.execute
                .mockResolvedValueOnce([{ affectedRows: 1 }]) // UPDATE usage_count
                .mockResolvedValueOnce([mockResults]) // SELECT query
                .mockResolvedValueOnce([{ affectedRows: 1 }]); // DELETE query

            const result = await verifyRefreshToken(rawToken, false);

            expect(result.valid).toBe(false);
            expect(result.reason).toBe('Token has been revoked');

            // Verify delete query was called
            expect(mockPool.execute).toHaveBeenCalledWith(
                expect.stringContaining('DELETE FROM refresh_tokens'),
                expect.arrayContaining([expect.any(String), 123])
            );
        });

        test('should handle expired tokens and invalidate them', async () => {
            const rawToken = crypto.randomBytes(64).toString('hex');
            const mockResults = [{
                user_id: 123,
                visitor_id: 456,
                valid: true,
                expiresAt: new Date(Date.now() - 24 * 60 * 60 * 1000), // Expired 1 day ago
                session_started_at: new Date()
            }];

            mockPool.execute
                .mockResolvedValueOnce([{ affectedRows: 1 }]) // UPDATE usage_count
                .mockResolvedValueOnce([mockResults]) // SELECT query
                .mockResolvedValueOnce([{ affectedRows: 1 }]); // UPDATE to invalidate

            const result = await verifyRefreshToken(rawToken, false);

            expect(result.valid).toBe(false);
            expect(result.reason).toBe('Token expired');
            expect(result.userId).toBe(123);

            // Verify invalidation query was called
            expect(mockPool.execute).toHaveBeenCalledWith(
                expect.stringContaining('UPDATE refresh_tokens'),
                expect.arrayContaining([expect.any(String)])
            );
        });

        test('should handle database errors', async () => {
            const rawToken = crypto.randomBytes(64).toString('hex');

            mockPool.execute.mockRejectedValue(new Error('Database connection failed'));

            await expect(verifyRefreshToken(rawToken, false)).rejects.toThrow('DB error verifying refresh token');
        });
    });

    describe('consumeAndVerifyRefreshToken', () => {
        test('should consume valid token successfully (one-time use)', async () => {
            const rawToken = crypto.randomBytes(64).toString('hex');
            const mockResults = [{
                user_id: 123,
                visitor_id: 456,
                valid: true,
                expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
                session_started_at: new Date()
            }];

            mockConnection.execute
                .mockResolvedValueOnce([{ affectedRows: 1 }]) // UPDATE usage_count with where usage_count = 0
                .mockResolvedValueOnce([mockResults]); // SELECT query

            const result = await consumeAndVerifyRefreshToken(rawToken, false);

            expect(result.valid).toBe(true);
            expect(result.userId).toBe(123);
            expect(result.visitor_id).toBe(456);
            expect(result.sessionTTL).toBeInstanceOf(Date);

            // Verify transaction was used
            expect(mockConnection.beginTransaction).toHaveBeenCalled();
            expect(mockConnection.commit).toHaveBeenCalled();
            expect(mockConnection.release).toHaveBeenCalled();
        });

        test('should handle already used tokens and revoke all user tokens', async () => {
            const rawToken = crypto.randomBytes(64).toString('hex');

            mockConnection.execute
                .mockResolvedValueOnce([{ affectedRows: 0 }]) // UPDATE failed - token already used
                .mockResolvedValueOnce([{ affectedRows: 5 }]); // Revoke all user tokens

            const result = await consumeAndVerifyRefreshToken(rawToken, false);

            expect(result.valid).toBe(false);
            expect(result.reason).toBe('Token already used, Please login again');

            // Verify all user tokens were revoked
            expect(mockConnection.execute).toHaveBeenCalledWith(
                expect.stringContaining('UPDATE refresh_tokens'),
                expect.arrayContaining([expect.any(String)])
            );

            expect(mockConnection.commit).toHaveBeenCalled();
        });

        test('should handle expired tokens during consumption', async () => {
            const rawToken = crypto.randomBytes(64).toString('hex');
            const mockResults = [{
                user_id: 123,
                visitor_id: 456,
                valid: true,
                expiresAt: new Date(Date.now() - 60000), // Expired 1 minute ago
                session_started_at: new Date()
            }];

            mockConnection.execute
                .mockResolvedValueOnce([{ affectedRows: 1 }]) // UPDATE usage_count
                .mockResolvedValueOnce([mockResults]) // SELECT query
                .mockResolvedValueOnce([{ affectedRows: 1 }]); // UPDATE to invalidate

            const result = await consumeAndVerifyRefreshToken(rawToken, false);

            expect(result.valid).toBe(false);
            expect(result.reason).toBe('Token expired');
            expect(result.userId).toBe(123);

            expect(mockConnection.commit).toHaveBeenCalled();
        });

        test('should rollback transaction on database errors', async () => {
            const rawToken = crypto.randomBytes(64).toString('hex');

            mockConnection.execute.mockRejectedValue(new Error('Database error'));

            await expect(consumeAndVerifyRefreshToken(rawToken, false)).rejects.toThrow('DB error verifying refresh token');

            expect(mockConnection.rollback).toHaveBeenCalled();
            expect(mockConnection.release).toHaveBeenCalled();
        });
    });

    describe('rotateRefreshToken', () => {
        test('should rotate token successfully', async () => {
            const ttl = 7 * 24 * 60 * 60 * 1000;
            const userId = 123;
            const oldToken = crypto.randomBytes(64).toString('hex');

            mockPool.execute.mockResolvedValue([{ affectedRows: 1 }]);

            const result = await rotateRefreshToken(ttl, userId, oldToken, false);

            expect(result.rotated).toBe(true);
            expect(result.raw).toMatch(/^[a-f0-9]{128}$/);
            expect(result.hashedToken).toMatch(/^[a-f0-9]{64}$/);
            expect(result.expiresAt).toBeInstanceOf(Date);

            // Verify database call with correct parameters
            expect(mockPool.execute).toHaveBeenCalledWith(
                expect.stringContaining('UPDATE refresh_tokens'),
                expect.arrayContaining([
                    result.hashedToken,
                    result.expiresAt,
                    expect.any(String), // old hashed token
                    userId
                ])
            );
        });

        test('should handle pre-hashed old token', async () => {
            const ttl = 7 * 24 * 60 * 60 * 1000;
            const userId = 123;
            const oldHashedToken = crypto.randomBytes(32).toString('hex');

            mockPool.execute.mockResolvedValue([{ affectedRows: 1 }]);

            const result = await rotateRefreshToken(ttl, userId, oldHashedToken, true);

            expect(result.rotated).toBe(true);

            // Should use the old token directly without hashing
            expect(mockPool.execute).toHaveBeenCalledWith(
                expect.stringContaining('UPDATE refresh_tokens'),
                expect.arrayContaining([
                    expect.any(String), // new hashed token
                    expect.any(Date), // expires at
                    oldHashedToken, // old token used directly
                    userId
                ])
            );
        });

        test('should return false when old token not found', async () => {
            const ttl = 7 * 24 * 60 * 60 * 1000;
            const userId = 123;
            const oldToken = crypto.randomBytes(64).toString('hex');

            mockPool.execute.mockResolvedValue([{ affectedRows: 0 }]); // No rows affected

            const result = await rotateRefreshToken(ttl, userId, oldToken, false);

            expect(result.rotated).toBe(false);
            expect(result.raw).toBeUndefined();
            expect(result.hashedToken).toBeUndefined();
            expect(result.expiresAt).toBeUndefined();
        });

        test('should handle database errors during rotation', async () => {
            const ttl = 7 * 24 * 60 * 60 * 1000;
            const userId = 123;
            const oldToken = crypto.randomBytes(64).toString('hex');

            mockPool.execute.mockRejectedValue(new Error('Database error'));

            await expect(rotateRefreshToken(ttl, userId, oldToken, false)).rejects.toThrow('DB error rotating refresh token');
        });
    });

    describe('revokeRefreshToken', () => {
        test('should revoke token successfully', async () => {
            const rawToken = crypto.randomBytes(64).toString('hex');

            mockPool.execute.mockResolvedValue([{ affectedRows: 1 }]);

            const result = await revokeRefreshToken(rawToken, false);

            expect(result.success).toBe(true);

            const expectedHash = crypto.createHash('sha256').update(rawToken).digest('hex');
            expect(mockPool.execute).toHaveBeenCalledWith(
                expect.stringContaining('UPDATE refresh_tokens SET valid = 0'),
                [expectedHash]
            );
        });

        test('should handle pre-hashed token', async () => {
            const hashedToken = crypto.randomBytes(32).toString('hex');

            mockPool.execute.mockResolvedValue([{ affectedRows: 1 }]);

            const result = await revokeRefreshToken(hashedToken, true);

            expect(result.success).toBe(true);

            // Should use the token directly without hashing
            expect(mockPool.execute).toHaveBeenCalledWith(
                expect.stringContaining('UPDATE refresh_tokens SET valid = 0'),
                [hashedToken]
            );
        });

        test('should handle database errors gracefully', async () => {
            const rawToken = crypto.randomBytes(64).toString('hex');

            mockPool.execute.mockRejectedValue(new Error('Database error'));

            const result = await revokeRefreshToken(rawToken, false);

            expect(result.success).toBe(false);
        });

        test('should still return success even if no rows affected', async () => {
            const rawToken = crypto.randomBytes(64).toString('hex');

            mockPool.execute.mockResolvedValue([{ affectedRows: 0 }]); // Token not found

            const result = await revokeRefreshToken(rawToken, false);

            expect(result.success).toBe(true); // Function doesn't check affected rows
        });
    });
});