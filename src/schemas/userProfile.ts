import { z } from "zod";

/**
 * Zod schema for the profile-update payload.
 *
 * SECURITY (Input Sanitization + OWASP API3 Mass Assignment):
 * - `.strict()` rejects ANY field not listed below with a 422. A client
 *   sending `{"displayName": "x", "role": "admin"}` or `{"isVerified": true}`
 *   is refused outright — privileged columns (id, role, email_verified,
 *   created_at, ...) are simply not representable in this schema, so they can
 *   never flow into the UPDATE statement.
 * - Every field has explicit type, length, and character-set constraints, so
 *   the database only ever stores data matching a known shape.
 * - All fields are optional (PATCH semantics) but `.refine` requires at least
 *   one, so empty no-op requests are rejected instead of silently succeeding.
 */

/**
 * SECURITY (XSS defense-in-depth, layer 1 of 2):
 * Strip ASCII control characters (optionally keeping \n and \t for the bio)
 * that have no business in profile text. This is *sanitization of shape*,
 * not HTML escaping — the API stores raw text and relies on contextual
 * output encoding at render time (layer 2, see routes/profile.ts response
 * notes). We deliberately do NOT try to "filter out <script>" here:
 * deny-list filtering is bypassable, while output encoding is not.
 */
// eslint-disable-next-line no-control-regex -- matching control chars is the point
const CONTROL_CHARS_EXCEPT_NEWLINE_TAB = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;
// eslint-disable-next-line no-control-regex
const ALL_CONTROL_CHARS = /[\x00-\x1F\x7F]/g;

const stripControlChars = (allowNewlines: boolean) => (value: string) =>
  value.replace(allowNewlines ? CONTROL_CHARS_EXCEPT_NEWLINE_TAB : ALL_CONTROL_CHARS, "");

// Unicode-aware "human name" pattern: letters, marks, digits, spaces and a
// small punctuation set. Rejects angle brackets, quotes, backslashes etc.,
// which shrinks the XSS/log-injection surface without blocking real names.
const DISPLAY_NAME_PATTERN = /^[\p{L}\p{M}\p{N} .,'\-]+$/u;

export const profileUpdateSchema = z
  .object({
    displayName: z
      .string()
      .trim()
      .min(1, "displayName must not be empty")
      .max(80, "displayName must be at most 80 characters")
      .regex(DISPLAY_NAME_PATTERN, "displayName contains unsupported characters")
      .transform(stripControlChars(false))
      .optional(),

    bio: z
      .string()
      .trim()
      .max(500, "bio must be at most 500 characters")
      .transform(stripControlChars(true))
      .optional(),

    /**
     * SECURITY (SSRF/open-redirect hygiene): the website URL is parsed with
     * the WHATWG URL parser and restricted to http(s). `javascript:`,
     * `data:`, `file:` and friends are rejected, so a stored profile link
     * can never become a script-executing or SSRF-pivoting URL when the
     * frontend renders it as an <a href>.
     */
    websiteUrl: z
      .string()
      .trim()
      .max(2048)
      .url("websiteUrl must be a valid URL")
      .refine((value) => {
        const protocol = new URL(value).protocol;
        return protocol === "https:" || protocol === "http:";
      }, "websiteUrl must use http or https")
      .optional(),

    /** Fixed vocabulary — an enum cannot carry an injection payload. */
    timezone: z
      .enum([
        "UTC",
        "America/New_York",
        "America/Chicago",
        "America/Denver",
        "America/Los_Angeles",
        "Europe/London",
        "Europe/Berlin",
        "Asia/Tokyo",
        "Asia/Kolkata",
        "Australia/Sydney",
      ])
      .optional(),
  })
  .strict() // <-- Mass-assignment guard: unknown keys are a hard error.
  .refine(
    (value) => Object.values(value).some((field) => field !== undefined),
    "At least one updatable field must be provided",
  );

export type ProfileUpdate = z.infer<typeof profileUpdateSchema>;

/**
 * The exhaustive list of columns a client is allowed to touch.
 *
 * SECURITY (Mass Assignment, second lock): the UPDATE statement in the
 * repository is built ONLY from keys present in this constant — never from
 * the request object's own keys. Even if the schema above were loosened by
 * a future refactor, unknown fields still could not reach SQL.
 */
export const UPDATABLE_COLUMNS = {
  displayName: "display_name",
  bio: "bio",
  websiteUrl: "website_url",
  timezone: "timezone",
} as const satisfies Record<keyof ProfileUpdate, string>;
