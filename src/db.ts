import Database from "better-sqlite3";
import { randomUUID } from "node:crypto";
import { UPDATABLE_COLUMNS, type ProfileUpdate } from "./schemas/userProfile.js";

/**
 * Data access layer. SQLite keeps this reference implementation
 * self-contained; every pattern here (prepared statements, positional
 * parameters, column allowlists) translates 1:1 to Postgres/MySQL.
 *
 * SECURITY (SQL Injection, OWASP A03):
 * - Every statement is prepared with `?` placeholders. User data travels
 *   ONLY as bound parameters — it is never concatenated or interpolated
 *   into SQL text, so `'; DROP TABLE users;--` is just a weird bio string.
 * - The one piece of dynamic SQL (the UPDATE's SET list) is assembled from
 *   the server-side UPDATABLE_COLUMNS constant, never from request keys.
 *
 * SECURITY (Least Privilege, AISDP #3): in a real deployment the app's DB
 * role should have only the DML it needs (no DDL, no other tables). SQLite
 * has no roles, so the equivalent here is that this module exports only the
 * narrow operations the API needs; there is no generic "run a query"
 * escape hatch.
 */

const db = new Database(process.env.DATABASE_FILE ?? ":memory:");
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'member',
    display_name  TEXT NOT NULL,
    bio           TEXT NOT NULL DEFAULT '',
    website_url   TEXT,
    timezone      TEXT NOT NULL DEFAULT 'UTC',
    updated_at    INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    family_id     TEXT NOT NULL,
    token_digest  TEXT NOT NULL UNIQUE,
    expires_at    INTEGER NOT NULL,
    revoked_at    INTEGER,
    replaced_by   TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(family_id);
`);

// ---------------------------------------------------------------- users ----

export interface UserCredentials {
  id: string;
  passwordHash: string;
}

/** The exact shape returned to clients — private columns (email, role, password_hash) are never selected. */
export interface PublicProfile {
  id: string;
  displayName: string;
  bio: string;
  websiteUrl: string | null;
  timezone: string;
  updatedAt: number;
}

const selectCredentials = db.prepare(
  `SELECT id, password_hash AS passwordHash FROM users WHERE email = ?`,
);

export function findUserCredentialsByEmail(email: string): UserCredentials | undefined {
  return selectCredentials.get(email) as UserCredentials | undefined;
}

/**
 * SECURITY (excessive data exposure, OWASP API3): the SELECT names public
 * columns explicitly — no `SELECT *` — so adding a sensitive column to the
 * table later can never silently leak it through this endpoint.
 */
const selectProfile = db.prepare(
  `SELECT id, display_name AS displayName, bio, website_url AS websiteUrl,
          timezone, updated_at AS updatedAt
     FROM users WHERE id = ?`,
);

export function getProfile(userId: string): PublicProfile | undefined {
  return selectProfile.get(userId) as PublicProfile | undefined;
}

export function updateProfile(userId: string, update: ProfileUpdate): PublicProfile | undefined {
  // Build the SET list from the server-side allowlist only (mass-assignment
  // lock #2 — see UPDATABLE_COLUMNS). Column names come from OUR constant;
  // values are bound as parameters.
  const assignments: string[] = [];
  const values: unknown[] = [];
  for (const [field, column] of Object.entries(UPDATABLE_COLUMNS)) {
    const value = update[field as keyof ProfileUpdate];
    if (value !== undefined) {
      assignments.push(`${column} = ?`);
      values.push(value);
    }
  }
  if (assignments.length === 0) return getProfile(userId);

  assignments.push("updated_at = ?");
  values.push(Date.now());
  values.push(userId);

  db.prepare(`UPDATE users SET ${assignments.join(", ")} WHERE id = ?`).run(...values);
  return getProfile(userId);
}

/** Seeding helper for dev/tests — not reachable from any HTTP route. */
export function createUser(input: {
  email: string;
  displayName: string;
  passwordHash: string;
}): { userId: string } {
  const userId = randomUUID();
  db.prepare(
    `INSERT INTO users (id, email, password_hash, display_name, updated_at)
     VALUES (?, ?, ?, ?, ?)`,
  ).run(userId, input.email, input.passwordHash, input.displayName, Date.now());
  return { userId };
}

// ------------------------------------------------------- refresh tokens ----

export interface RefreshTokenRecord {
  id: string;
  userId: string;
  familyId: string;
  tokenDigest: string;
  expiresAt: number;
  revokedAt: number | null;
  replacedBy: string | null;
}

const insertToken = db.prepare(
  `INSERT INTO refresh_tokens (id, user_id, family_id, token_digest, expires_at, revoked_at, replaced_by)
   VALUES (?, ?, ?, ?, ?, ?, ?)`,
);

export function insertRefreshToken(record: RefreshTokenRecord): void {
  insertToken.run(
    record.id,
    record.userId,
    record.familyId,
    record.tokenDigest,
    record.expiresAt,
    record.revokedAt,
    record.replacedBy,
  );
}

const selectToken = db.prepare(
  `SELECT id, user_id AS userId, family_id AS familyId, token_digest AS tokenDigest,
          expires_at AS expiresAt, revoked_at AS revokedAt, replaced_by AS replacedBy
     FROM refresh_tokens WHERE token_digest = ?`,
);

export function findRefreshTokenByDigest(digest: string): RefreshTokenRecord | undefined {
  return selectToken.get(digest) as RefreshTokenRecord | undefined;
}

const rotateToken = db.prepare(
  `UPDATE refresh_tokens SET replaced_by = ?, revoked_at = ? WHERE id = ?`,
);

export function markRefreshTokenRotated(id: string, replacedById: string): void {
  rotateToken.run(replacedById, Date.now(), id);
}

/**
 * SECURITY (Invalidation): revocation is a server-side state change on the
 * whole family — every outstanding token in the chain dies at once, which
 * is what makes logout and theft-response real rather than cosmetic.
 */
const revokeFamily = db.prepare(
  `UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL`,
);

export function revokeRefreshTokenFamily(familyId: string): void {
  revokeFamily.run(Date.now(), familyId);
}
