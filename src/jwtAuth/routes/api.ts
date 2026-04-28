import express, { Router } from "express";
import { getFingerPrint } from "~~/middleware/fingerPrint.js";
import { checkForActiveMfa } from "~~/middleware/isMfaActive.js";
import { requireAccessToken } from "~~/middleware/requireAccessToken.js";
import { requireRefreshToken } from "~~/middleware/requireRefreshToken.js";
import { contentType } from "~~/middleware/validateContentType.js";
import { protectRoute } from "~~/middleware/verifyJwt.js";
import { getLogger } from "~~/utils/logger.js";
import { apiTokensController } from "~~/controllers/apiTokens.js";
import { verifyApiTokenController } from "~~/controllers/verifyApiToken.js";


export const apiProtectedRoutes = () =>  {
    const router = Router();
    
router.post('/api/manage/:action',
    requireAccessToken,
    requireRefreshToken,
    getFingerPrint,
    checkForActiveMfa,
    protectRoute,
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
     apiTokensController
    )

router.get('/api/manage/:action',
    requireAccessToken,
    requireRefreshToken,
    getFingerPrint,
    checkForActiveMfa,
    protectRoute,
    apiTokensController
    )
    
    return router;
}

export const apiVerificationRoute = () => {
    const router = Router();
    router.get('/api/public/verify', verifyApiTokenController);
    return router;
}