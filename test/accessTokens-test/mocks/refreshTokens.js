// Mock for refresh tokens to prevent actual database calls during access token tests
import { vi } from 'vitest';

// Mock the refresh token functions that might be called during access token tests
vi.mock('../../../src/refreshTokens.js', () => ({
  rotateRefreshToken: vi.fn().mockResolvedValue({
    rotated: true,
    raw: 'mock-refresh-token',
    hashedToken: 'mock-hashed-token',
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
  }),
  verifyRefreshToken: vi.fn().mockResolvedValue({
    valid: true,
    userId: 123,
    visitor_id: 456
  }),
  generateRefreshToken: vi.fn().mockResolvedValue({
    raw: 'mock-refresh-token',
    hashedToken: 'mock-hashed-token',
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
  }),
  revokeRefreshToken: vi.fn().mockResolvedValue(undefined)
}));