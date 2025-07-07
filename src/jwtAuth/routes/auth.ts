import express, { Router } from "express";
import { handleSignUp } from "../controllers/signUpController.js";
import { contentType } from "../middleware/validateContentType.js";
import { OAuthHandler } from "../controllers/OAuth.js";
import { handleLogin } from "../controllers/loginController.js";
const router = Router();


// @ts-check
/**
 * @module jwtAuth/routes
 *
/**
 *  @description
 * Part of the default configuration.
 * Main authentication routes: signup, login, and OAuth.
 * 
 * @type {import('express').Router}
 * @see {@link ./routes/auth.js}
 * @example
 * // mounted under /signup, /login, and  /auth/OAth/:providerName
 * app.use(authenticationRoutes);
 */


router.post(
  '/signup',
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
  (req, res, next) => {
    const cookie = req.cookies.canary_id
  if (!cookie) {
      res.status(400).json({error: `Cookie not provided`});
      return;
    };
    const ip = req.ip
    next()
  },
handleSignUp
);
router.post(
  '/login',
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
  (req, res, next) => {
    const cookie = req.cookies.canary_id
    const ip = req.ip
    next()
  },
handleLogin
);

router.post(
  '/auth/OAth/:providerName',
  contentType('application/json'),
  express.json({ 
    limit: '4kb',
    verify: (req, res, buf) => {
      if (!buf.toString()) {
        console.log('EMPTY_BODY')
        throw new Error('403');
      }
    }
  }), 
  (req, res, next) => {
    const cookie = req.cookies.canary_id
    if (!cookie) {
      res.status(400).json({error: `Cookie not provided`});
      return;
     };
    const ip = req.ip
    console.log(`Entering Route`)
    next()
  },

OAuthHandler
);


export default router;