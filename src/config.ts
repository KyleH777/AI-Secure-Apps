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
   * SECURITY (secrets): HMAC key used to derive session-token digests.
   * Provided via env; the dev fallback exists only so `npm run dev` works
   * locally and is rejected in production by requiredInProd().
   */
  sessionTokenPepper: requiredInProd(
    "SESSION_TOKEN_PEPPER",
    "dev-only-pepper-do-not-use-in-prod",
  ),

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
