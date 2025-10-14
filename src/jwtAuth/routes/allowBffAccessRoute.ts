import { allowBffAccess } from "../controllers/allowBffAccess.js";
import { getAccessTokenPayload } from "../controllers/getPayloadMeta.js";
import { getRefreshTokenMetaData } from "../controllers/getRefreshTokenMetaData.js";
import { cookieOnly } from "../middleware/postGuard.js";
import { requireAccessToken } from "../middleware/requireAccessToken.js";
import { requireRefreshToken } from "../middleware/requireRefreshToken.js";
import { protectRoute } from "../middleware/verifyJwt.js";
import { Router } from "express";

/**
 * @summary BFF authorization and token metadata routes.
 * @description
 * - `GET /secret/data` returns protected resource after access checks.
 * - `GET /secret/metadata` returns decoded access token payload and TTL hints.
 *
 * Both routes are protected by `requireAccessToken`, `requireRefreshToken`,
 * and `protectRoute`.
 *
 * @see ../controllers/allowBffAccess.ts
 * @see ../controllers/getPayloadMeta.ts
 */
const router = Router();


router.get('/secret/data', 
  requireAccessToken,
  requireRefreshToken,
  protectRoute,
  allowBffAccess
)
router.get('/secret/accesstoken/metadata', 
  requireAccessToken,
  requireRefreshToken,
  protectRoute,
  cookieOnly,
  getAccessTokenPayload
)

router.get('/secret/refreshtoken/metadata', 
  requireRefreshToken,
  cookieOnly,
  getRefreshTokenMetaData
)
export default router;
