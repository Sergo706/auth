import { Request, Response } from "express";

/**
 * Final 404 handler returning a standardized JSON error shape.
 * Should be registered after all routes and middleware.
 *
 * Response: `404 { error: string }`.
 */
export function notFoundHandler(
  req: Request,
  res: Response,
) {
 res.status(404).json({ error: "The page you are looking for doesn't exists"});
}
