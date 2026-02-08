import express, { Router } from "express"; 
import { linkMfaVerification, linkPasswordVerification } from "../middleware/verifyTempLink.js";
import { verifyMFA } from "../middleware/verifyEmailMFA.js";
import { contentType } from "../middleware/validateContentType.js";
import { verifyNewPassword } from "../middleware/verifyPasswordReset.js";
import { initPasswordReset } from "../controllers/initPasswordReset.js";
import { detectBots } from "@riavzon/botdetector"; 
import { getLogger } from "../utils/logger.js";
import { getFingerPrint } from "../middleware/fingerPrint.js";
import { verifyCustomMfa } from "../controllers/verifyCustomMfaController.js";
import { customMfaFlowsVerification } from "../middleware/verifyTempLink.js";
import { requireRefreshToken } from "../middleware/requireRefreshToken.js";
import { initCustomMfaFlow } from "../controllers/initCustomMfaFlow.js";

const router = Router();

router
.route("/auth/verify-mfa/:visitor")
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
    requireRefreshToken,
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
  .get(customMfaFlowsVerification)
    .post(
      customMfaFlowsVerification,
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
      verifyCustomMfa
    );

  
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

  router.route("/auth/reset-password/:visitor")
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
    verifyNewPassword
  );

export default router;


