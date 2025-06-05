import { Request, Response } from "express";
import { verifyRefreshToken } from "../refreshTokens.js";
import { generateAccessToken } from "../accsessTokens.js";

export const rotateAccessToken =  async (req: Request, res: Response) => {
        const rawRefreshToken = req.cookies.session;
   
        try {
         const result = await verifyRefreshToken(rawRefreshToken);
         if (!result.valid) {
            res.status(401).json({error: result.reason})
            return;
         }

         const accessToken = generateAccessToken({
            id: result.userId!,
            visitor_id: result.visitor_id!,
        });
        res.status(200).json({accessToken: accessToken });
        return;

      } catch(err) {
          console.warn(`Error Rotating access token: ${err}`)
          res.status(500).json({error: `Error Rotating access token: ${err}`})
       }
    };