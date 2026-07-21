# Security for people making apps with AI!

# AI-Secure-Apps

A reference implementation of the **AI-Assisted Secure Development Protocol
(AISDP)**: a secure API endpoint, token-based authentication, an accessible
frontend component, and a pre-commit security review — every control
exercised by runnable end-to-end checks.

Stack: TypeScript, Express, Zod, jose (JWT), SQLite (prepared statements
only), vanilla HTML/CSS/JS frontend.

## Endpoints

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `POST` | `/api/v1/auth/login` | — | Email + password → 15-min JWT access token + rotating refresh cookie |
| `POST` | `/api/v1/auth/refresh` | cookie | Rotates the refresh token, returns a fresh access token |
| `POST` | `/api/v1/auth/logout` | cookie | Revokes the refresh-token family server-side |
| `GET` | `/api/v1/users/me/profile` | Bearer JWT | Fetch the caller's profile |
| `PATCH` | `/api/v1/users/me/profile` | Bearer JWT | Update `displayName`, `bio`, `websiteUrl`, `timezone` |
| `GET` | `/healthz` | — | Liveness probe (rate-limited) |

## Quick start

```bash
npm ci
npm run dev        # boots on :3000, prints dev login credentials to the console
npm run smoke      # end-to-end security test suite (40 checks)
npm run typecheck
```

```bash
# 1. Login (use the seeded credentials from the dev_user_seeded log line)
curl -i -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"dev@example.com","password":"<printed-password>"}'

# 2. Use the returned accessToken
curl -X PATCH http://localhost:3000/api/v1/users/me/profile \
  -H "Authorization: Bearer <accessToken>" \
  -H "Content-Type: application/json" \
  -d '{"displayName": "Ada Lovelace", "timezone": "Europe/London"}'
```

The accessible checkout demo is static — open `frontend/checkout/index.html`
in a browser.

## Security controls → where they live

### API (AISDP Template 1)

| Requirement | Implementation |
| --- | --- |
| Strict schema validation | `src/schemas/userProfile.ts` — Zod `.strict()`; unknown fields → 422; per-field type/length/charset/protocol constraints |
| Mass assignment | Two locks: strict schema (privileged fields unrepresentable) + `UPDATABLE_COLUMNS` allowlist building the SQL `SET` list (`src/db.ts`) |
| SQL injection | Prepared statements with bound `?` parameters everywhere; no `SELECT *` |
| XSS | Input shape constraints + control-char stripping, `http(s)`-only URLs, JSON-only responses with `nosniff` + `default-src 'none'` CSP |
| Rate limiting | `src/middleware/rateLimit.ts` — sliding window per user/IP; separate tighter per-IP budget for auth endpoints; `RateLimit-*`/`Retry-After` headers |
| Error handling | `src/errors.ts` + `src/middleware/errorHandler.ts` — one JSON envelope `{error:{code,message,requestId}}`; stack traces never leave the server |
| CORS | `src/middleware/cors.ts` — exact-match origin allowlist; no `*` code path exists; `Vary: Origin` |
| IDOR / BOLA | Routes address `/users/me/…` — the target row comes only from the verified token's `sub` |

### Authentication (AISDP Template 2 — IAM)

| Requirement | Implementation |
| --- | --- |
| Secrets management | `JWT_SECRET` / `REFRESH_TOKEN_PEPPER` from env (`.env.example`); production refuses to boot without them; no secret in code |
| Access tokens | `src/auth/jwt.ts` — 15-minute HS256 JWTs; algorithm pinned on verify (no `alg:none`); `iss`/`aud`/`exp` always validated |
| Refresh tokens | `src/auth/refreshTokens.ts` + `src/auth/cookies.ts` — opaque 256-bit tokens in HttpOnly + Secure + SameSite=Strict cookies scoped to `/api/v1/auth`; never localStorage |
| Rotation | Every refresh rotates the token; reuse of a rotated token revokes the entire family (RFC 9700 model) |
| Invalidation | Logout revokes the whole family server-side; `src/auth/passwords.ts` — scrypt hashes, timing-uniform login, no user enumeration |

### Accessibility (AISDP Template 3)

`frontend/checkout/` — WCAG 2.1 AA multi-step checkout form: semantic
landmarks, native controls only, full keyboard operation with visible
`:focus-visible` rings, focus-managed step changes, `aria-live` status,
error-summary pattern, 4.5:1+ contrast, reflow-safe at 200 %+ zoom.
Full audit: `docs/ARIA-AUDIT-checkout.md` (verified by a 19-check
keyboard-driven Chromium run).

### DevSecOps review (AISDP Template 4)

`docs/SECURITY-REVIEW.md` — pre-publication scan of this repo: secret scan
(clean), typosquat check (clean), disclosure review (clean), supply chain
(remediated: exact version pins + lockfile `sha512` integrity hashes; use
`npm ci` in CI).

## Production notes

- Back the rate limiter with Redis when running multiple instances.
- Swap SQLite for Postgres/MySQL by porting `src/db.ts`; keep the prepared
  statement + column allowlist patterns; grant the app's DB role only the
  DML it needs.
- Terminate TLS at the proxy and keep `trust proxy` set to the real hop count.
- Serve the SPA and API from the same site so the SameSite=Strict refresh
  cookie flows; keep access tokens in memory only.
