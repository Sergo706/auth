import express, { Router } from "express"; 
import { linkMfaVerification, linkPasswordVerification } from "../middleware/verifyTempLink.js";
import { verifyMFA } from "../middleware/verifyEmailMFA.js";
import { contentType } from "../middleware/validateContentType.js";
import { verifyNewPassword } from "../middleware/verifyPasswordReset.js";
import { initPasswordReset } from "../controllers/initPasswordReset.js";
import { detectBots } from '@riavzon/bot-detector';
import { getLogger } from "../utils/logger.js";
import { getFingerPrint } from "../middleware/fingerPrint.js";
import { verifyCustomMfa } from "../controllers/verifyCustomMfaController.js";
import { customMfaFlowsVerification } from "../middleware/verifyTempLink.js";
import { requireRefreshToken } from "../middleware/requireRefreshToken.js";
import { initCustomMfaFlow } from "../controllers/initCustomMfaFlow.js";
import { requireAccessToken } from "../middleware/requireAccessToken.js";
import { protectRoute } from "../middleware/verifyJwt.js";
import { updateEmailController } from "../controllers/updateEmailController.js";

const router = Router();

router
.route("/auth/verify-mfa")
.get(linkMfaVerification)
  .post(
    linkMfaVerification,
    contentType('application/json'),
      express.json({ 
        limit: '1kb',
        verify: (req, res, buf) => {
          if (!buf.toString()) {
            const log = getLogger().child({service: 'auth', branch: 'routes', type: 'Json checker'})
            log.warn('EMPTY_BODY')
            throw new Error('403');
          }
        }
      }), 
      detectBots,
    getFingerPrint,
    verifyMFA
  );

  router.post('/custom/mfa/:reason',
    contentType('application/json'),
    requireAccessToken,
    requireRefreshToken,
    getFingerPrint,
    protectRoute,
    express.json({ 
        limit: '1kb',
        verify: (req, res, buf) => {
          if (!buf.toString()) {
           const log = getLogger().child({service: 'auth', branch: 'routes', type: 'Json checker'})
           log.warn('EMPTY_BODY')
            throw new Error('403');
          }
        }
      }),
     initCustomMfaFlow
  )

  router
  .route("/auth/verify-custom-mfa")
  .get(
    requireAccessToken,
    requireRefreshToken,
    getFingerPrint,
    protectRoute,
    customMfaFlowsVerification
  )
    .post(
      contentType('application/json'),
      requireAccessToken,
      requireRefreshToken,
      getFingerPrint,
      protectRoute,
        express.json({ 
          limit: '1kb',
          verify: (req, res, buf) => {
            if (!buf.toString()) {
              const log = getLogger().child({service: 'auth', branch: 'routes', type: 'Json checker'})
              log.warn('EMPTY_BODY')
              throw new Error('403');
            }
          }
        }), 
      customMfaFlowsVerification,
      detectBots,
      verifyCustomMfa
    );

    router.post("/update/email", 
        contentType('application/json'),
        requireAccessToken,
        requireRefreshToken,
        getFingerPrint,
        protectRoute,
        express.json({ 
          limit: '1kb',
          verify: (req, res, buf) => {
            if (!buf.toString()) {
            const log = getLogger().child({service: 'auth', branch: 'routes', type: 'Json checker'})
            log.warn('EMPTY_BODY')
              throw new Error('403');
            }
          }
      }),
      customMfaFlowsVerification,
      detectBots,
      updateEmailController
    )
  
  router.post(
    "/auth/forgot-password",
    contentType('application/json'),
    express.json({ 
        limit: '1kb',
        verify: (req, res, buf) => {
          if (!buf.toString()) {
           const log = getLogger().child({service: 'auth', branch: 'routes', type: 'Json checker'})
           log.warn('EMPTY_BODY')
            throw new Error('403');
          }
        }
      }),
      initPasswordReset
)

  router.route("/auth/reset-password")
  .get(linkPasswordVerification)
    .post(
    linkPasswordVerification,
    contentType('application/json'),
        express.json({ 
        limit: '1kb',
        verify: (req, res, buf) => {
          if (!buf.toString()) {
          const log = getLogger().child({service: 'auth', branch: 'routes', type: 'Json checker'})
          log.warn('EMPTY_BODY')
            throw new Error('403');
          }
        }
      }),   
      detectBots,
      getFingerPrint,
    verifyNewPassword
  );

export default router;


