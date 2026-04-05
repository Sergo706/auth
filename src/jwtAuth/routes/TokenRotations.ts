import { Router } from "express";
import { cookieOnly } from "../middleware/postGuard.js";
import { requireRefreshToken } from "../middleware/requireRefreshToken.js";
import { handleLogout } from "../controllers/logout.js";
import { rotateCredentials } from "../controllers/rotateOnEveryUse.js";
import { requireAccessToken } from "../middleware/requireAccessToken.js";
import { getFingerPrint } from "../middleware/fingerPrint.js";
const router = Router();

router.post(
'/auth/user/refresh-session',
  requireRefreshToken,
  cookieOnly,
  getFingerPrint,
  rotateCredentials
);

router.post(
'/auth/logout',
  requireRefreshToken,
  requireAccessToken,
  cookieOnly,
  handleLogout
)

export default router;