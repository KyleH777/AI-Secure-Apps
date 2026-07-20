import type { NextFunction, Request, Response } from "express";
import { config } from "../config.js";

/**
 * Strict CORS middleware.
 *
 * SECURITY (Cross-Origin policy):
 * - The Origin header is compared for EXACT equality against the configured
 *   allowlist (scheme + host + port). No wildcard `*`, no regex, no
 *   suffix-matching (suffix checks like `.endsWith("example.com")` are a
 *   classic bypass via `evilexample.com`).
 * - A disallowed origin gets a response with NO CORS headers at all — the
 *   browser then blocks the cross-origin read. We do not 403 the request
 *   itself, because CORS is a browser read-protection, not authentication;
 *   auth is enforced separately by requireAuth.
 * - `Vary: Origin` prevents a shared cache from serving one origin's
 *   CORS-approved response to a different origin.
 * - Allowed headers/methods are enumerated explicitly rather than echoing
 *   the request's Access-Control-Request-* values back.
 */
export function strictCors(req: Request, res: Response, next: NextFunction): void {
  const origin = req.headers.origin;

  res.setHeader("Vary", "Origin");

  if (origin && config.allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Methods", "GET, PATCH, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
    res.setHeader("Access-Control-Max-Age", "600");
  }

  if (req.method === "OPTIONS") {
    // Preflight: answer without invoking auth/business logic.
    res.status(204).end();
    return;
  }

  next();
}
