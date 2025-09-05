import { vi, MockedFunction } from 'vitest';
import * as refreshTokens from '../../src/refreshTokens.js';

// Mock the refreshTokens module
vi.mock('../../src/refreshTokens.js', () => ({
  generateRefreshToken: vi.fn(),
  rotateRefreshToken: vi.fn(),
  verifyRefreshToken: vi.fn(),
}));

export const mockedGenerateRefreshToken = refreshTokens.generateRefreshToken as MockedFunction<typeof refreshTokens.generateRefreshToken>;
export const mockedRotateRefreshToken = refreshTokens.rotateRefreshToken as MockedFunction<typeof refreshTokens.rotateRefreshToken>;
export const mockedVerifyRefreshToken = refreshTokens.verifyRefreshToken as MockedFunction<typeof refreshTokens.verifyRefreshToken>;