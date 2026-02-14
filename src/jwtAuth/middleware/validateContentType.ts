import { Request, Response, NextFunction, RequestHandler } from "express";
import { getLogger } from "../utils/logger.js";


/**
 * @description
 * Enforces that the `Content-Type` header matches the expected type.
 * If not, responds with HTTP 415 Unsupported Media Type.
 *
 * @param {string} expected
 *   The expected MIME type (e.g., `'application/json'`).
 *
 * @returns {import('express').RequestHandler}
 *   An Express middleware that checks `Content-Type` and returns 415 if it does not match.
 *
 * @see {@link ./middleware/validateContentType.js}
 *
 * @example
 * // Only allow JSON bodies
 * app.post('/api/data', contentType('application/json'), handler);
 */
export function contentType(expected: string): RequestHandler {
    return(req: Request, res: Response, next: NextFunction) => {
        const log = getLogger().child({service: 'auth', branch: 'middleware', type: 'contentType'})
        if (!req.is(expected)) {
            log.warn('unexpected content type')
            res.status(403).json({error: 'not allowed.'})
            return;
        };
        return next();
    };
  };