import { Router, type Request, type Response } from "express";
import { requireAuth } from "../middleware/auth.js";
import { rateLimit } from "../middleware/rateLimit.js";
import { getProfile, updateProfile } from "../db.js";
import { profileUpdateSchema } from "../schemas/userProfile.js";
import { AppError } from "../errors.js";
import { logger } from "../logger.js";

/**
 * Profile endpoints:
 *   GET   /api/v1/users/me/profile
 *   PATCH /api/v1/users/me/profile
 *
 * SECURITY (IDOR/BOLA, OWASP API1): the resource is addressed as `me`.
 * There is no `:userId` route parameter and no user id accepted in the
 * body — the target row comes exclusively from the authenticated session.
 * A caller structurally cannot ask to update someone else's profile.
 *
 * Middleware order matters: auth runs BEFORE rateLimit so authenticated
 * callers are limited per-user (not per shared IP), while unauthenticated
 * garbage still gets limited per-IP and rejected with 401.
 */
export const profileRouter = Router();

profileRouter.get("/users/me/profile", requireAuth, rateLimit, (req: Request, res: Response) => {
  const profile = getProfile(req.auth!.userId);
  if (!profile) throw new AppError("not_found", "Profile not found.");
  res.json({ data: profile });
});

profileRouter.patch("/users/me/profile", requireAuth, rateLimit, (req: Request, res: Response) => {
  /**
   * SECURITY (Input Sanitization): safeParse validates req.body against the
   * strict Zod schema. On failure we return a 422 whose `details` contain
   * ONLY the field path and our own schema-authored messages — Zod's raw
   * error objects (which can echo attacker input back) are not serialized
   * wholesale.
   */
  const parsed = profileUpdateSchema.safeParse(req.body);
  if (!parsed.success) {
    const details = parsed.error.issues.map((issue) => ({
      field: issue.path.join(".") || "(root)",
      message: issue.message,
    }));
    throw new AppError("validation_failed", "Request payload failed validation.", details);
  }

  // From here on, only the validated & transformed object is used —
  // req.body is dead. parsed.data cannot contain unknown keys (strict
  // schema) and updateProfile() additionally maps through a column
  // allowlist, so mass assignment is blocked at two independent layers.
  const profile = updateProfile(req.auth!.userId, parsed.data);
  if (!profile) throw new AppError("not_found", "Profile not found.");

  // Audit log: who changed what (field names only — never values, which
  // could put PII into logs).
  logger.info("profile_updated", {
    requestId: req.requestId,
    userId: req.auth!.userId,
    fields: Object.keys(parsed.data),
  });

  /**
   * SECURITY (XSS, layer 2 of 2): the response is application/json with
   * X-Content-Type-Options: nosniff (see securityHeaders). res.json()
   * escapes per JSON rules, so the payload can't break out of the JSON
   * context. Stored text is returned raw by design — the consuming frontend
   * must apply contextual output encoding (e.g. React's default escaping,
   * or explicit HTML-entity encoding in templates) when rendering
   * displayName/bio, and use the validated http(s)-only websiteUrl for
   * hrefs. Encoding at the render context, not at storage, is what actually
   * neutralizes stored XSS.
   */
  res.json({ data: profile });
});
