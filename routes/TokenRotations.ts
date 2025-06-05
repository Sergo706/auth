import { Router } from "express";
import { cookieOnly } from "../middleware/postGuard.js";
import fingerPrint from '../../botDetector/routes/visitorLog.js';
import {rotateAccessToken} from '../controllers/rotateAccessToken.js';
import { rotateRefreshTokens } from '../controllers/rotateRefreshTokens.js';
import { requireRefreshToken } from "../middleware/requireRefreshToken.js";
import { handleLogout } from "../controllers/logout.js";
import { rotateCredentials } from "../controllers/rotateOnEveryUse.js";
const router = Router();


router.post(
'/auth/refresh-access',
  fingerPrint, 
  requireRefreshToken,
  cookieOnly,
rotateAccessToken
);

router.post(
'/auth/user/refresh-session',
  fingerPrint,
  requireRefreshToken,
  cookieOnly,
 rotateRefreshTokens
);

router.post(
'/auth/logout',
  fingerPrint,
  requireRefreshToken,
  cookieOnly,
  handleLogout
)

router.post(
  '/auth/refresh-session/rotate-every',
  fingerPrint,
  requireRefreshToken,
  cookieOnly, 
  rotateCredentials
);
    
export default router;