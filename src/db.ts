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
 * role should have only SELECT/UPDATE on `users` and SELECT on `sessions` —
 * no DDL, no access to other tables. SQLite has no roles, so the equivalent
 * here is that this module exports only the narrow operations the API
 * needs; there is no generic "run a query" escape hatch.
 */

const db = new Database(process.env.DATABASE_FILE ?? ":memory:");
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    role          TEXT NOT NULL DEFAULT 'member',
    display_name  TEXT NOT NULL,
    bio           TEXT NOT NULL DEFAULT '',
    website_url   TEXT,
    timezone      TEXT NOT NULL DEFAULT 'UTC',
    updated_at    INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_digest  TEXT NOT NULL UNIQUE,
    expires_at    INTEGER NOT NULL
  );
`);

export interface SessionRecord {
  id: string;
  userId: string;
  tokenDigest: string;
  expiresAt: number;
}

/** The exact shape returned to clients — private columns (email, role) are never selected. */
export interface PublicProfile {
  id: string;
  displayName: string;
  bio: string;
  websiteUrl: string | null;
  timezone: string;
  updatedAt: number;
}

const selectSession = db.prepare(
  `SELECT id, user_id AS userId, token_digest AS tokenDigest, expires_at AS expiresAt
     FROM sessions WHERE token_digest = ?`,
);

export function findSessionByTokenDigest(digest: string): SessionRecord | undefined {
  return selectSession.get(digest) as SessionRecord | undefined;
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

/** Test/dev seeding helper — not reachable from any HTTP route. */
export function seedUserWithSession(input: {
  email: string;
  displayName: string;
  tokenDigest: string;
  sessionTtlMs: number;
}): { userId: string; sessionId: string } {
  const userId = randomUUID();
  const sessionId = randomUUID();
  db.prepare(
    `INSERT INTO users (id, email, display_name, updated_at) VALUES (?, ?, ?, ?)`,
  ).run(userId, input.email, input.displayName, Date.now());
  db.prepare(
    `INSERT INTO sessions (id, user_id, token_digest, expires_at) VALUES (?, ?, ?, ?)`,
  ).run(sessionId, userId, input.tokenDigest, Date.now() + input.sessionTtlMs);
  return { userId, sessionId };
}
