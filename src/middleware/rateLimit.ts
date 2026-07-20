import type { NextFunction, Request, Response } from "express";
import { config } from "../config.js";
import { AppError } from "../errors.js";

/**
 * Sliding-window rate limiter (factory — each limiter gets its own budget).
 *
 * SECURITY (OWASP API4 Unrestricted Resource Consumption / brute-force):
 * - True sliding window (per-client timestamp log), not a fixed window, so
 *   a client cannot double its budget by straddling a window boundary.
 * - Keyed by authenticated user id when available, falling back to client
 *   IP. Keying by user prevents one NAT'd office IP from exhausting the
 *   budget for everyone behind it, and prevents an authenticated attacker
 *   from resetting their budget by rotating IPs.
 * - The auth endpoints use a separate, much smaller per-IP budget
 *   (config.authRateLimit) — credential stuffing gets throttled long before
 *   the general API budget would kick in.
 * - Emits standard RateLimit-* headers plus Retry-After on rejection so
 *   well-behaved clients can back off without guessing.
 *
 * NOTE: state is in-process, which is correct for a single instance. Behind
 * a load balancer, back this with Redis (same algorithm: ZADD + ZREMRANGEBYSCORE
 * + ZCARD in a pipeline) so all instances share one budget.
 */

interface WindowState {
  /** Millisecond timestamps of requests inside the current window, oldest first. */
  timestamps: number[];
}

export interface RateLimitOptions {
  windowMs: number;
  maxRequests: number;
  /** Namespaces this limiter's buckets so limiters never share budgets. */
  name: string;
}

export function createRateLimit(options: RateLimitOptions) {
  const { windowMs, maxRequests, name } = options;
  const buckets = new Map<string, WindowState>();

  // Periodically drop empty buckets so a scan of many IPs can't grow memory forever.
  setInterval(() => {
    const cutoff = Date.now() - windowMs;
    for (const [key, state] of buckets) {
      while (state.timestamps.length > 0 && (state.timestamps[0] as number) <= cutoff) {
        state.timestamps.shift();
      }
      if (state.timestamps.length === 0) buckets.delete(key);
    }
  }, 60_000).unref();

  function clientKey(req: Request): string {
    // Prefer the authenticated principal; anonymous requests fall back to IP.
    // req.ip honors Express's `trust proxy` setting configured in app.ts, so
    // it reflects the real client, not the load balancer.
    const userId = req.auth?.userId;
    return userId ? `${name}:user:${userId}` : `${name}:ip:${req.ip ?? "unknown"}`;
  }

  return function rateLimit(req: Request, res: Response, next: NextFunction): void {
    const now = Date.now();
    const cutoff = now - windowMs;

    const key = clientKey(req);
    let state = buckets.get(key);
    if (!state) {
      state = { timestamps: [] };
      buckets.set(key, state);
    }

    // Slide the window: discard entries older than windowMs.
    while (state.timestamps.length > 0 && (state.timestamps[0] as number) <= cutoff) {
      state.timestamps.shift();
    }

    if (state.timestamps.length >= maxRequests) {
      const oldest = state.timestamps[0] as number;
      const retryAfterSeconds = Math.max(1, Math.ceil((oldest + windowMs - now) / 1000));
      res.setHeader("RateLimit-Limit", String(maxRequests));
      res.setHeader("RateLimit-Remaining", "0");
      res.setHeader("Retry-After", String(retryAfterSeconds));
      // SECURITY: the 429 body reveals nothing about limiter internals beyond
      // what the standard headers already communicate.
      next(new AppError("rate_limited", "Too many requests. Please retry later."));
      return;
    }

    state.timestamps.push(now);
    res.setHeader("RateLimit-Limit", String(maxRequests));
    res.setHeader("RateLimit-Remaining", String(maxRequests - state.timestamps.length));
    next();
  };
}

/** General API limiter (per user, IP fallback). */
export const rateLimit = createRateLimit({ ...config.rateLimit, name: "api" });

/** SECURITY: tight per-IP limiter for credential endpoints (brute-force control). */
export const authRateLimit = createRateLimit({ ...config.authRateLimit, name: "auth" });
