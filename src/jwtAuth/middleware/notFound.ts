import { Request, Response } from "express";

export function notFoundHandler(
  req: Request,
  res: Response,
) {
 res.status(404).send("The page you are looking for doesn't exists");
}