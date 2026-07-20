import { randomUUID } from "node:crypto";
import type { NextFunction, Request, Response } from "express";

/**
 * Assigns every request a server-generated UUID.
 *
 * SECURITY (log integrity): the id is always generated server-side — an
 * inbound X-Request-Id header is ignored, so clients cannot forge
 * correlation ids or inject CRLF/log-spoofing payloads through them. The id
 * is echoed back in the response header and in error envelopes so users can
 * quote it to support without the API ever exposing internals.
 */

declare module "express-serve-static-core" {
  interface Request {
    requestId?: string;
  }
}

export function requestId(req: Request, res: Response, next: NextFunction): void {
  const id = randomUUID();
  req.requestId = id;
  res.setHeader("X-Request-Id", id);
  next();
}
