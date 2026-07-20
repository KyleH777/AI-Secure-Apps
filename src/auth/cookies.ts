import type { Request, Response } from "express";
import { config } from "../config.js";

/**
 * Refresh-token cookie handling.
 *
 * SECURITY (Token Storage — the "not localStorage" requirement):
 * The refresh token lives ONLY in an HTTP-Only cookie:
 * - HttpOnly  → invisible to JavaScript, so XSS cannot exfiltrate it.
 * - Secure    → never sent over plaintext HTTP (enforced in production;
 *               relaxed only for http://localhost development).
 * - SameSite=Strict → the browser refuses to attach it to ANY cross-site
 *               request, which neutralizes CSRF against the auth endpoints.
 * - Path-scoped to /api/v1/auth → the token is not even sent with normal
 *               API calls, only to login/refresh/logout.
 * The short-lived ACCESS token is returned in the JSON body for the SPA to
 * keep in memory (never persisted to localStorage/sessionStorage).
 */

export function setRefreshCookie(res: Response, rawToken: string): void {
  const maxAgeSeconds = Math.floor(config.refreshToken.ttlMs / 1000);
  const attributes = [
    `${config.refreshToken.cookieName}=${rawToken}`,
    `Max-Age=${maxAgeSeconds}`,
    `Path=${config.refreshToken.cookiePath}`,
    "HttpOnly",
    "SameSite=Strict",
    ...(config.isProduction ? ["Secure"] : []),
  ];
  res.append("Set-Cookie", attributes.join("; "));
}

export function clearRefreshCookie(res: Response): void {
  res.append(
    "Set-Cookie",
    [
      `${config.refreshToken.cookieName}=`,
      "Max-Age=0",
      `Path=${config.refreshToken.cookiePath}`,
      "HttpOnly",
      "SameSite=Strict",
      ...(config.isProduction ? ["Secure"] : []),
    ].join("; "),
  );
}

/**
 * Minimal, allocation-light cookie parser. Only the refresh cookie is ever
 * read; values are percent-decoded defensively and anything malformed is
 * simply ignored (never thrown to the client).
 */
export function readRefreshCookie(req: Request): string | null {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const pair of header.split(";")) {
    const eq = pair.indexOf("=");
    if (eq === -1) continue;
    const name = pair.slice(0, eq).trim();
    if (name !== config.refreshToken.cookieName) continue;
    const value = pair.slice(eq + 1).trim();
    // Refresh tokens are base64url — reject anything shaped differently
    // before it reaches crypto or the database.
    return /^[A-Za-z0-9_-]{20,128}$/.test(value) ? value : null;
  }
  return null;
}
