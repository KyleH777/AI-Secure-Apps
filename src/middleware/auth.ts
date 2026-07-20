import { createHmac, timingSafeEqual } from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import { config } from "../config.js";
import { findSessionByTokenDigest } from "../db.js";
import { AppError } from "../errors.js";

/**
 * Bearer-token authentication middleware.
 *
 * SECURITY (Broken Authentication / least privilege, AISDP #3):
 * - Opaque random session tokens, NOT user-controlled data, identify the
 *   caller. The route then operates only on `req.auth.userId` — the client
 *   can never name which user's profile to update (no `userId` in the URL
 *   or body), which eliminates BOLA/IDOR on this endpoint by construction.
 * - Tokens are stored only as HMAC-SHA256 digests (keyed with a server-side
 *   pepper from the environment). A leaked database does not leak usable
 *   session tokens, and the pepper never appears in code or logs.
 * - Digest comparison uses timingSafeEqual to rule out timing side-channels.
 * - Sessions carry an expiry; expired sessions are rejected server-side
 *   regardless of what the client claims.
 * - Failure responses are uniform ("Authentication required.") so an
 *   attacker cannot distinguish unknown vs. expired vs. malformed tokens.
 */

declare module "express-serve-static-core" {
  interface Request {
    auth?: { userId: string; sessionId: string };
  }
}

export function digestSessionToken(rawToken: string): string {
  return createHmac("sha256", config.sessionTokenPepper).update(rawToken).digest("hex");
}

const BEARER_PATTERN = /^Bearer ([A-Za-z0-9_-]{20,128})$/;

export function requireAuth(req: Request, _res: Response, next: NextFunction): void {
  const header = req.headers.authorization;
  const match = header ? BEARER_PATTERN.exec(header) : null;
  if (!match) {
    next(new AppError("unauthorized", "Authentication required."));
    return;
  }

  const digest = digestSessionToken(match[1] as string);
  const session = findSessionByTokenDigest(digest);
  if (!session) {
    next(new AppError("unauthorized", "Authentication required."));
    return;
  }

  // Constant-time re-check of the digest defends against any lookup-layer
  // shortcuts (e.g. a future cache with prefix matching).
  const stored = Buffer.from(session.tokenDigest, "hex");
  const presented = Buffer.from(digest, "hex");
  if (stored.length !== presented.length || !timingSafeEqual(stored, presented)) {
    next(new AppError("unauthorized", "Authentication required."));
    return;
  }

  if (session.expiresAt <= Date.now()) {
    next(new AppError("unauthorized", "Authentication required."));
    return;
  }

  req.auth = { userId: session.userId, sessionId: session.id };
  next();
}
