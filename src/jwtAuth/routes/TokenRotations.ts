import { Router } from "express";
import { cookieOnly } from "../middleware/postGuard.js";
import {rotateAccessToken} from '../controllers/rotateAccessToken.js';
import { rotateRefreshTokens } from '../controllers/rotateRefreshTokens.js';
import { requireRefreshToken } from "../middleware/requireRefreshToken.js";
import { handleLogout } from "../controllers/logout.js";
import { rotateCredentials } from "../controllers/rotateOnEveryUse.js";
import { getConfiguration } from "../config/configuration.js";
import { requireAccessToken } from "../middleware/requireAccessToken.js";
const router = Router();


router.post(
'/auth/refresh-access',
  requireRefreshToken,
  cookieOnly,
rotateAccessToken
);

router.post(
'/auth/user/refresh-session',
  requireRefreshToken,
  cookieOnly,
 async (req, res, next) => {
    try {
      const { jwt: { refresh_tokens } } = getConfiguration();

      if (refresh_tokens.rotateOnEveryAccessExpiry) {
        await rotateCredentials(req, res);
      } else {
        await rotateRefreshTokens(req, res);
      }
    } catch (err) {
      next(err);
    }
  }
);

router.post(
'/auth/logout',
  requireRefreshToken,
  requireAccessToken,
  cookieOnly,
  handleLogout
)

router.post(
  '/auth/refresh-session/rotate-every',
  requireRefreshToken,
  cookieOnly, 
  rotateCredentials
);
    
export default router;