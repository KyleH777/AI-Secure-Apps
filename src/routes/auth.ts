import { Router, type Request, type Response, type NextFunction } from "express";
import { z } from "zod";
import { signAccessToken } from "../auth/jwt.js";
import { DUMMY_HASH_PROMISE, verifyPassword } from "../auth/passwords.js";
import {
  issueRefreshTokenFamily,
  revokeByRawToken,
  rotateRefreshToken,
} from "../auth/refreshTokens.js";
import { clearRefreshCookie, readRefreshCookie, setRefreshCookie } from "../auth/cookies.js";
import { config } from "../config.js";
import { findUserCredentialsByEmail } from "../db.js";
import { AppError } from "../errors.js";
import { logger } from "../logger.js";
import { authRateLimit } from "../middleware/rateLimit.js";

/**
 * Auth endpoints:
 *   POST /api/v1/auth/login    { email, password } -> access token + refresh cookie
 *   POST /api/v1/auth/refresh  (cookie)            -> new access token + ROTATED refresh cookie
 *   POST /api/v1/auth/logout   (cookie)            -> revokes the refresh-token family
 *
 * Token model (IAM requirements):
 * - ACCESS token: 15-minute JWT returned in the JSON body. The SPA keeps it
 *   in memory only — never localStorage/sessionStorage, so XSS cannot
 *   harvest a long-lived credential.
 * - REFRESH token: opaque, HttpOnly + Secure + SameSite=Strict cookie
 *   scoped to /api/v1/auth, rotated on every use with family-wide reuse
 *   detection (see auth/refreshTokens.ts).
 */
export const authRouter = Router();

/** SECURITY: strict schema — extra fields rejected; email normalized; bounded lengths. */
const loginSchema = z
  .object({
    email: z.string().trim().toLowerCase().email().max(254),
    // Only bound the length (DoS guard for scrypt); never constrain password
    // *content* — composition rules weaken passphrases.
    password: z.string().min(8).max(256),
  })
  .strict();

authRouter.post(
  "/auth/login",
  authRateLimit,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const parsed = loginSchema.safeParse(req.body);
      if (!parsed.success) {
        // SECURITY: login validation failures return the SAME message as
        // wrong credentials — field-level detail here would aid enumeration.
        throw new AppError("unauthorized", "Invalid email or password.");
      }

      const { email, password } = parsed.data;
      const credentials = findUserCredentialsByEmail(email);

      // SECURITY (user enumeration): unknown email still burns a full
      // scrypt verification against a dummy hash so timing is uniform.
      const hashToCheck = credentials?.passwordHash ?? (await DUMMY_HASH_PROMISE);
      const passwordOk = await verifyPassword(password, hashToCheck);

      if (!credentials || !passwordOk) {
        logger.warn("login_failed", { requestId: req.requestId });
        throw new AppError("unauthorized", "Invalid email or password.");
      }

      const accessToken = await signAccessToken(credentials.id);
      const { rawToken } = issueRefreshTokenFamily(credentials.id);
      setRefreshCookie(res, rawToken);

      logger.info("login_succeeded", { requestId: req.requestId, userId: credentials.id });
      res.json({
        data: {
          accessToken,
          tokenType: "Bearer",
          expiresIn: config.jwt.accessTokenTtlSeconds,
        },
      });
    } catch (err) {
      next(err);
    }
  },
);

authRouter.post(
  "/auth/refresh",
  authRateLimit,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const presented = readRefreshCookie(req);
      if (!presented) throw new AppError("unauthorized", "Authentication required.");

      // SECURITY (rotation + reuse detection) happens inside
      // rotateRefreshToken; on any failure the cookie is cleared so the
      // client stops replaying a dead token.
      const rotation = rotateRefreshToken(presented);
      if (!rotation.ok) {
        clearRefreshCookie(res);
        throw new AppError("unauthorized", "Authentication required.");
      }

      const accessToken = await signAccessToken(rotation.userId);
      setRefreshCookie(res, rotation.rawToken);
      res.json({
        data: {
          accessToken,
          tokenType: "Bearer",
          expiresIn: config.jwt.accessTokenTtlSeconds,
        },
      });
    } catch (err) {
      next(err);
    }
  },
);

authRouter.post("/auth/logout", authRateLimit, (req: Request, res: Response) => {
  /**
   * SECURITY (Invalidation): logout revokes the ENTIRE refresh-token family
   * server-side — not just this cookie — so copies of the chain on other
   * devices/tabs die too. The 15-minute access token needs no denylist: its
   * remaining life is the accepted, tightly bounded exposure window (add a
   * jti denylist here if your threat model can't tolerate even that).
   * Idempotent: logging out twice, or with no cookie, still returns 204.
   */
  const presented = readRefreshCookie(req);
  if (presented) revokeByRawToken(presented);
  clearRefreshCookie(res);
  res.status(204).end();
});
