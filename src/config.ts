/**
 * Centralized, environment-driven configuration.
 *
 * SECURITY (AISDP #1 — "Never trust AI with secrets"):
 * No secrets are hardcoded anywhere in this codebase. Everything sensitive
 * (session signing key, allowed origins) is injected via environment
 * variables at deploy time. The app refuses to boot in production without
 * them, rather than falling back to an insecure default.
 */

const isProduction = process.env.NODE_ENV === "production";

function requiredInProd(name: string, devFallback: string): string {
  const value = process.env[name];
  if (value && value.length > 0) return value;
  if (isProduction) {
    // Fail closed: never boot a production server with a known-default secret.
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return devFallback;
}

export const config = {
  isProduction,

  port: Number.parseInt(process.env.PORT ?? "3000", 10),

  /**
   * SECURITY (CORS): The allowlist is an explicit, comma-separated set of
   * origins. There is deliberately no code path that emits
   * `Access-Control-Allow-Origin: *`.
   */
  allowedOrigins: (process.env.ALLOWED_ORIGINS ?? "http://localhost:5173")
    .split(",")
    .map((origin) => origin.trim())
    .filter((origin) => origin.length > 0),

  /**
   * SECURITY (secrets): HMAC key used to derive refresh-token digests before
   * they touch the database. Provided via env; the dev fallback exists only
   * so `npm run dev` works locally and is rejected in production by
   * requiredInProd().
   */
  refreshTokenPepper: requiredInProd(
    "REFRESH_TOKEN_PEPPER",
    "dev-only-pepper-do-not-use-in-prod",
  ),

  /**
   * JWT access-token settings (IAM requirements).
   *
   * SECURITY (Token Lifecycle):
   * - HS256 signing key comes from the environment, never code (AISDP #1).
   *   Must be >= 32 bytes; enforced at boot in auth/jwt.ts.
   * - Access tokens are short-lived (15 minutes) so a leaked token has a
   *   tightly bounded blast radius; long-lived state lives only in the
   *   rotating refresh token.
   * - iss/aud are pinned and verified on every request so a token minted
   *   for a different service in the same org can never be replayed here.
   */
  jwt: {
    secret: requiredInProd(
      "JWT_SECRET",
      "dev-only-jwt-secret-at-least-32-bytes-long!",
    ),
    issuer: process.env.JWT_ISSUER ?? "https://auth.ai-secure-apps.local",
    audience: process.env.JWT_AUDIENCE ?? "ai-secure-apps-api",
    accessTokenTtlSeconds: 15 * 60, // 15 minutes
  },

  refreshToken: {
    cookieName: "refresh_token",
    ttlMs: 14 * 24 * 60 * 60 * 1000, // 14 days absolute lifetime per family
    /**
     * SECURITY: the cookie is scoped to the auth router only — the browser
     * never attaches the refresh token to profile/API requests, shrinking
     * both exposure and CSRF surface.
     */
    cookiePath: "/api/v1/auth",
  },

  /** Tighter per-IP budget for credential endpoints (brute-force control). */
  authRateLimit: {
    windowMs: Number.parseInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS ?? "60000", 10),
    maxRequests: Number.parseInt(process.env.AUTH_RATE_LIMIT_MAX ?? "10", 10),
  },

  rateLimit: {
    /** Sliding-window size in milliseconds. */
    windowMs: Number.parseInt(process.env.RATE_LIMIT_WINDOW_MS ?? "60000", 10),
    /** Max requests per window per client (IP or authenticated user). */
    maxRequests: Number.parseInt(process.env.RATE_LIMIT_MAX ?? "30", 10),
  },

  /**
   * SECURITY (request-size DoS): cap on JSON body size. Oversized payloads
   * are rejected by express.json() before they reach validation.
   */
  maxJsonBodyBytes: "16kb",
} as const;
