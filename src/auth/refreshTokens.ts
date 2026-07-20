import { createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { config } from "../config.js";
import {
  findRefreshTokenByDigest,
  insertRefreshToken,
  markRefreshTokenRotated,
  revokeRefreshTokenFamily,
  type RefreshTokenRecord,
} from "../db.js";

/**
 * Rotating refresh tokens with reuse detection.
 *
 * SECURITY (Token Lifecycle + Invalidation):
 * - Tokens are 256-bit random values — opaque, unguessable, carrying no
 *   claims to tamper with.
 * - Only a peppered HMAC-SHA256 digest is stored. A database leak yields
 *   nothing usable without the environment-held pepper.
 * - AUTOMATIC ROTATION: every refresh invalidates the presented token and
 *   issues a new one in the same "family" (one family per login/device).
 * - REUSE DETECTION: presenting an already-rotated or revoked token is
 *   treated as theft — the ENTIRE family is revoked immediately, forcibly
 *   logging out whichever party holds the stolen chain. This is the OAuth2
 *   BCP (RFC 9700) refresh-token rotation model.
 * - Families carry an absolute expiry (14 days) so rotation cannot extend a
 *   session forever.
 * - Logout revokes the whole family server-side (true invalidation, not
 *   just cookie deletion).
 */

export function digestRefreshToken(rawToken: string): string {
  return createHmac("sha256", config.refreshTokenPepper).update(rawToken).digest("hex");
}

export function generateRawRefreshToken(): string {
  return randomBytes(32).toString("base64url");
}

export interface IssuedRefreshToken {
  rawToken: string;
  record: RefreshTokenRecord;
}

/** Start a brand-new family (called at login). */
export function issueRefreshTokenFamily(userId: string): IssuedRefreshToken {
  const rawToken = generateRawRefreshToken();
  const record: RefreshTokenRecord = {
    id: randomUUID(),
    userId,
    familyId: randomUUID(),
    tokenDigest: digestRefreshToken(rawToken),
    expiresAt: Date.now() + config.refreshToken.ttlMs,
    revokedAt: null,
    replacedBy: null,
  };
  insertRefreshToken(record);
  return { rawToken, record };
}

export type RotationResult =
  | { ok: true; rawToken: string; userId: string }
  | { ok: false };

/**
 * Validate a presented refresh token and rotate it. Any failure path
 * returns a bare `{ok: false}` — callers translate that to a uniform 401
 * with no detail about WHY (unknown/expired/reused are indistinguishable
 * to a client, which denies attackers an oracle).
 */
export function rotateRefreshToken(rawToken: string): RotationResult {
  const digest = digestRefreshToken(rawToken);
  const record = findRefreshTokenByDigest(digest);
  if (!record) return { ok: false };

  // Constant-time confirmation of the digest match from the lookup layer.
  const a = Buffer.from(record.tokenDigest, "hex");
  const b = Buffer.from(digest, "hex");
  if (a.length !== b.length || !timingSafeEqual(a, b)) return { ok: false };

  // SECURITY (reuse detection): a token that was already rotated or revoked
  // is being replayed — someone (client or attacker) holds a stale copy.
  // Kill the whole family so the stolen chain dies with it.
  if (record.revokedAt !== null || record.replacedBy !== null) {
    revokeRefreshTokenFamily(record.familyId);
    return { ok: false };
  }

  if (record.expiresAt <= Date.now()) {
    revokeRefreshTokenFamily(record.familyId);
    return { ok: false };
  }

  // Rotate: mint the successor in the same family, keeping the family's
  // ABSOLUTE expiry (rotation refreshes access, never extends the session).
  const nextRaw = generateRawRefreshToken();
  const next: RefreshTokenRecord = {
    id: randomUUID(),
    userId: record.userId,
    familyId: record.familyId,
    tokenDigest: digestRefreshToken(nextRaw),
    expiresAt: record.expiresAt,
    revokedAt: null,
    replacedBy: null,
  };
  insertRefreshToken(next);
  markRefreshTokenRotated(record.id, next.id);

  return { ok: true, rawToken: nextRaw, userId: record.userId };
}

/** Revoke the family behind a presented token (logout). Idempotent. */
export function revokeByRawToken(rawToken: string): void {
  const record = findRefreshTokenByDigest(digestRefreshToken(rawToken));
  if (record) revokeRefreshTokenFamily(record.familyId);
}
