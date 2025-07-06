import { Response, request } from "express";
type cookies = {
    httpOnly: boolean,
    sameSite: boolean | "lax" | "strict" | "none";
    maxAge?: number; 
    secure: boolean; 
    expires?: Date;
    domain?: string;
    path?: string; 
  };



/**
 * @description
 * Generates a serialized `Set-Cookie` header string.  
 * If `name` starts with `"__Host-"`, defaults applied:
 *   - `options.secure = true`  
 *   - `options.path = '/'`  
 *   - `delete options.domain;`  
 * If `name` starts with `"__Secure-"`, defaults applied:
 *   - `options.secure = true`
 *
 * @param {import('express').Response} res
 *   The Express response object (to which the cookie will be attached).
 * @param {string} name
 *   The cookie name (e.g. `"__Host-sessionId"`).
 * @param {string} value
 *   The cookie value.
 * @param {import('express').CookieOptions} [options]
 *   Optional cookie settings (e.g. `httpOnly`, `sameSite`, `expires`, `domain`, `path`, etc.).
 *
 * @returns {string}
 *   The full `Set-Cookie` header string (e.g. `"name=value; HttpOnly; Secure; Path=/; …"`).
 *
 * @see {@link ./cookieGenerator.js}
 *
 * @example
 * import { makeCookie } from './cookieGenerator.js';
 *
 * const cookieHeader = makeCookie(res, '__Host-sessionId', sessionId, {
 *   httpOnly: true,
 *   sameSite: 'strict',
 *   expires: new Date(Date.now() + 86400000),
 *   path: '/',
 * });
 * res.setHeader('Set-Cookie', cookieHeader);
 */
export function makeCookie(res: Response, name: string, value: string, options: cookies) {

  if (name.startsWith("__Host-")) {
    options.secure = true;
    options.path = "/";
    delete options.domain;
  }

  if (name.startsWith("__Secure-")) {
    options.secure = true;
  }

    res.cookie(name, value, {
      httpOnly: options.httpOnly,
      sameSite: options.sameSite,
      maxAge: options.maxAge,
      secure: options.secure,
      expires: options.expires,
      domain: options.domain,
      path: options.path,
      });
}


