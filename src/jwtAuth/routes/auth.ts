import express, { Router } from "express";
import { handleSignUp } from "../controllers/signUpController.js";
import { contentType } from "../middleware/validateContentType.js";
import { GoogleSignUp } from "../controllers/googleOuath.js";
import { handleLogin } from "../controllers/loginController.js";
const router = Router();


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
  '/auth/google',
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

GoogleSignUp
);


export default router;