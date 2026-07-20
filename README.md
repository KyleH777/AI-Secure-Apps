# AI-Secure-Apps — Secure User Profile API

A reference implementation of an AISDP-compliant API endpoint for **user
profile updates**, built with TypeScript, Express, Zod, and SQLite
(prepared statements only). Every security control is exercised by a
runnable end-to-end smoke test.

## Endpoints

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/api/v1/users/me/profile` | Bearer | Fetch the caller's profile |
| `PATCH` | `/api/v1/users/me/profile` | Bearer | Update `displayName`, `bio`, `websiteUrl`, `timezone` |
| `GET` | `/healthz` | none | Liveness probe (rate-limited) |

## Quick start

```bash
npm install
npm run dev        # boots on :3000, prints a dev bearer token to the console
npm run smoke      # end-to-end security test suite (23 checks)
npm run typecheck
```

```bash
TOKEN=...          # from the dev_session_seeded log line
curl -X PATCH http://localhost:3000/api/v1/users/me/profile \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"displayName": "Ada Lovelace", "timezone": "Europe/London"}'
```

## Security controls → where they live

| Requirement | Implementation |
| --- | --- |
| Strict schema validation | `src/schemas/userProfile.ts` — Zod `.strict()` object; unknown/extra fields → 422; per-field type, length, charset, and protocol constraints |
| Mass assignment | Two independent locks: the strict schema (privileged fields unrepresentable) and the `UPDATABLE_COLUMNS` allowlist that builds the SQL `SET` list in `src/db.ts` |
| SQL injection | `src/db.ts` — prepared statements with bound `?` parameters everywhere; no string interpolation of user data; explicit column lists (no `SELECT *`) |
| XSS | Layered: input shape constraints + control-char stripping (`schemas`), `http(s)`-only URL validation, JSON-only responses with `nosniff` + `default-src 'none'` CSP (`middleware/securityHeaders.ts`), contextual output-encoding contract documented at the response site |
| Rate limiting | `src/middleware/rateLimit.ts` — true sliding window, keyed per authenticated user (falls back to IP), standard `RateLimit-*`/`Retry-After` headers |
| Error handling | `src/errors.ts` + `src/middleware/errorHandler.ts` — single JSON envelope `{error: {code, message, requestId}}`; stack traces and parser internals never leave the server; 5xx logged with request correlation ids |
| CORS | `src/middleware/cors.ts` — exact-match origin allowlist from `ALLOWED_ORIGINS`; no `*` code path exists; `Vary: Origin`; enumerated methods/headers |
| IDOR / BOLA | Route is `/users/me/...` — the target row comes only from the authenticated session; no user id is accepted from the client |
| Auth & least privilege | `src/middleware/auth.ts` — opaque bearer tokens stored as peppered HMAC-SHA256 digests, constant-time compare, server-side expiry, uniform 401s |
| Secrets | None in the repo. `SESSION_TOKEN_PEPPER` and `ALLOWED_ORIGINS` come from the environment (`.env.example`); production refuses to boot without them |
| DoS hygiene | 16 KB JSON body cap, JSON-only content type, bucket sweeping in the limiter, `trust proxy` pinned to one hop so `X-Forwarded-For` can't be spoofed |

## Configuration

See `.env.example`. Notable: `ALLOWED_ORIGINS` (comma-separated exact
origins), `SESSION_TOKEN_PEPPER` (required in production), and
`RATE_LIMIT_WINDOW_MS` / `RATE_LIMIT_MAX`.

## Production notes

- Back the rate limiter with Redis when running multiple instances (the
  algorithm translates directly; see the note in `rateLimit.ts`).
- Swap SQLite for Postgres/MySQL by porting `src/db.ts`; keep the prepared
  statement + column allowlist patterns. Grant the app's DB role only the
  DML it needs (no DDL).
- Terminate TLS at the proxy and keep `trust proxy` set to the real hop
  count.
