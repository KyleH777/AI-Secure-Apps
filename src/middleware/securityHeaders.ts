import type { NextFunction, Request, Response } from "express";

/**
 * Baseline security headers for a JSON API.
 *
 * SECURITY (XSS defense-in-depth, layer 2 supports):
 * - X-Content-Type-Options: nosniff — a JSON response can never be sniffed
 *   into being executed as HTML/JS, which closes the classic
 *   "reflected JSON as HTML" XSS vector.
 * - Content-Security-Policy: default-src 'none' — if an attacker ever does
 *   coerce a browser into rendering an API response as a document, nothing
 *   can load or execute.
 * - X-Frame-Options / frame-ancestors — API responses cannot be framed for
 *   clickjacking-style tricks.
 * - Cache-Control: no-store — profile data is personal; it must not land in
 *   shared/proxy caches.
 * - X-Powered-By is disabled in app.ts so the stack is not fingerprintable.
 */
export function securityHeaders(_req: Request, res: Response, next: NextFunction): void {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cache-Control", "no-store");
  next();
}
