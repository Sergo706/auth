import { Request, Response } from 'express';
import { getConfiguration } from '../config/configuration.js';
import { getLogger } from '../utils/logger.js';
import { getLimiters } from '../utils/limiters/protectedEndpoints/tokensLimiters.js';
import { makeConsecutiveCache } from '../utils/limiters/utils/consecutiveCache.js';
import { guard } from '../utils/limiters/utils/guard.js';
import { toDigestHex } from '../utils/hashChecker.js';
import { verifyRefreshToken } from '../../refreshTokens.js';
const consecutiveForRefreshMeta = makeConsecutiveCache<{countData: number}>(2000, 1000 * 60 * 60 * 12);

/**
 * Returns metadata for the current refresh session:
 * - Time until refresh token expiration
 * - Time until maximum session life
 * - Rotation threshold recommendation
 *
 * Does not disclose user identifiers or token data.
 * Requires only refresh cookies; does not mutate state.
 */
export async function getRefreshTokenMetaData(req: Request, res: Response) {
  const log = getLogger().child({ service: 'auth', branch: 'refresh token', type: 'getRefreshTokenMetaData' });
  const { jwt } = getConfiguration();
  const rawRefreshToken = req.cookies.session;
  const canary = req.cookies.canary_id;

  if (!rawRefreshToken || !canary) {
    log.warn('Missing refresh cookies');
    res.status(401).json({ authorized: false, reason: 'Login required' });
    return;
  }


  const { refreshTokenLimiter } = getLimiters();
  const {input: hashed} = await toDigestHex(rawRefreshToken)
  if (!(await guard(refreshTokenLimiter, hashed, consecutiveForRefreshMeta, 1, 'Refresh Token', log, res))) return;

  const iatCookie = Number(req.cookies.iat);

  try {
    let sessionStartedAtMs: number | null = Number.isFinite(iatCookie) ? iatCookie : null;

    const verify = await verifyRefreshToken(rawRefreshToken);

    if (!verify.valid && verify.reason !== 'Token expired') {
        log.warn({reason: verify.reason},'Not a valid refresh token');
        res.status(401).json({ authorized: false, reason: 'Login required' });
        return;
    }

    if (!sessionStartedAtMs) {
        sessionStartedAtMs = verify.sessionStartedAt?.getTime() as number;
    }

    const refreshTtl = jwt.refresh_tokens.refresh_ttl;
    const REFRESH_PERCENTAGE = 0.15;
    const REFRESH_THRESHOLD = refreshTtl * REFRESH_PERCENTAGE;

    const expiresAtMs: number = verify.expiresAt?.getTime() as number ?? sessionStartedAtMs + refreshTtl;

    const msUntilExp = Math.max(0, expiresAtMs - Date.now());
    const shouldRotate = msUntilExp <= REFRESH_THRESHOLD;

    const sessionMaxLife = jwt.refresh_tokens.MAX_SESSION_LIFE; 
    const msUntilSessionMax = Math.max(0, sessionStartedAtMs + sessionMaxLife - Date.now());


    log.info('Refresh metadata retrieved');
    res.status(200).json({
      authorized: true,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      date: new Date().toISOString(),
      msUntilExp,
      refreshThreshold: REFRESH_THRESHOLD,
      shouldRotate,
      msUntilSessionMaxLife: msUntilSessionMax
    });
  } catch (err) {
    log.error({ err }, 'Error getting refresh metadata');
    res.status(500).json({ authorized: false, reason: 'Server error' });
  }
}
