import { allowBffAccess } from "../controllers/allowBffAccess.js";
import { getAccessTokenPayload } from "../controllers/getPayloadMeta.js";
import { requireAccessToken } from "../middleware/requireAccessToken.js";
import { requireRefreshToken } from "../middleware/requireRefreshToken.js";
import { protectRoute } from "../middleware/verifyJwt.js";
import { Router } from "express";

/**
 * @summary Router for BFF authorization endpoint (`GET /secret/data`).
 * Minimal router that wires auth middleware before the controller.
 * @see ../controllers/allowBffAccess.ts
 */
const router = Router();


router.get('/secret/data', 
  requireAccessToken,
  requireRefreshToken,
  protectRoute,
  allowBffAccess
)
router.get('/secret/metadata', 
  requireAccessToken,
  requireRefreshToken,
  protectRoute,
  getAccessTokenPayload
)
export default router;
