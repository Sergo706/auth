import express, { Router } from "express"; 
import { linkMfaVerification, linkPasswordVerification } from "../middleware/verifyTempLink.js";
import { verifyMFA } from "../middleware/verifyEmailMFA.js";
import { contentType } from "../middleware/validateContentType.js";
import { verifyNewPassword } from "../middleware/verifyPasswordReset.js";
import { initPasswordReset } from "../controllers/initPasswordReset.js";
import { detectBots } from "@riavzon/botdetector"; 

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
            console.log('EMPTY_BODY')
            throw new Error('403');
          }
        }
      }), 
      detectBots,
    verifyMFA
  );

  
  router.post(
    "/auth/forgot-password",
    contentType('application/json'),
    express.json({ 
        limit: '1kb',
        verify: (req, res, buf) => {
          if (!buf.toString()) {
            console.log('EMPTY_BODY')
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
            console.log('EMPTY_BODY')
            throw new Error('403');
          }
        }
      }),   
      detectBots,
    verifyNewPassword
  );

export default router;


