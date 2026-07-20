import type { NextFunction, Request, Response } from "express";
import { verifyAccessToken } from "../auth/jwt.js";
import { AppError } from "../errors.js";

/**
 * JWT bearer authentication middleware.
 *
 * SECURITY (Verification + least privilege, AISDP #3):
 * - Every protected request re-verifies signature (HS256 pinned), `exp`,
 *   `iss`, and `aud` via auth/jwt.ts — nothing is trusted from a previous
 *   request or a cache.
 * - The route layer then operates only on `req.auth.userId` (the verified
 *   `sub` claim) — the client can never name which user's data to touch (no
 *   userId in the URL or body), which eliminates BOLA/IDOR by construction.
 * - Failure responses are uniform ("Authentication required.") whether the
 *   token is missing, malformed, expired, mis-audienced, or forged — no
 *   oracle for attackers.
 * - Access tokens are 15-minute-lived and never stored server-side; revoking
 *   long-term access happens at the refresh-token layer (see auth/refreshTokens.ts).
 */

declare module "express-serve-static-core" {
  interface Request {
    auth?: { userId: string };
  }
}

const BEARER_PATTERN = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/;

export async function requireAuth(req: Request, _res: Response, next: NextFunction): Promise<void> {
  const header = req.headers.authorization;
  const match = header ? BEARER_PATTERN.exec(header) : null;
  if (!match) {
    next(new AppError("unauthorized", "Authentication required."));
    return;
  }

  const claims = await verifyAccessToken(match[1] as string);
  if (!claims) {
    next(new AppError("unauthorized", "Authentication required."));
    return;
  }

  req.auth = { userId: claims.sub };
  next();
}
