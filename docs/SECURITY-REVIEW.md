# DevSecOps Pre-Commit Security Review

Scope: the entire repository, reviewed before publication to a public
GitHub repository (per the AISDP DevSecOps checklist). Date: 2026-07-20.

## 1. Secret Scanning

Patterns scanned: API keys (`AKIA…`, `api_key`), JWT/HMAC secrets, private
key blocks (`BEGIN RSA/EC/OPENSSH`), database connection strings
(`postgres://`, `mongodb://`, `mysql://`, `redis://`, `amqp://`), literal
`secret/password/token/pepper = "…"` assignments, and RFC 1918 internal IP
addresses.

**Result: no hardcoded secrets.** Items reviewed and accepted:

| Location | What it is | Verdict |
| --- | --- | --- |
| `src/config.ts` | `dev-only-*` fallback strings for `JWT_SECRET` / `REFRESH_TOKEN_PEPPER` | Accepted — clearly labeled, and `requiredInProd()` makes the app **refuse to boot in production** without real env values, so the fallback can never protect real data |
| `src/server.ts:23` | Dev seed password interpolated into a log hint | Accepted — value is `randomBytes(12)` generated fresh per boot, printed to the local console only, and the whole block is guarded out of production |
| `scripts/smoke.ts` | Literals like `"definitely-wrong-password"` | Accepted — negative-test fixtures, intentionally invalid |
| `.env.example` | `JWT_SECRET=` / `REFRESH_TOKEN_PEPPER=` | Accepted — empty placeholders with generation instructions; real `.env` is gitignored |

`.gitignore` excludes `.env`, `.env.*` (except `.env.example`), SQLite
files, and `node_modules/` — no state or secret files can be committed
accidentally.

## 2. Dependency Hygiene

Runtime dependencies (4): `better-sqlite3`, `express`, `jose`, `zod`.
Dev dependencies (5): `@types/*`, `tsx`, `typescript`.

- **Typosquatting**: every name verified against the canonical npm package
  (correct spellings: `better-sqlite3` not `better-sqlite`, `jose` — the
  panva IETF JOSE implementation, `zod` not `zodd`). No post-install
  scripts beyond `better-sqlite3`'s standard prebuilt-binary fetch.
- **Freshness**: all dependencies are current stable majors (Express 4.22,
  jose 6, zod 3). `npm audit`: **0 vulnerabilities** at time of review.
- **Footprint**: 9 direct dependencies total is a deliberately small attack
  surface; crypto (scrypt, HMAC, `timingSafeEqual`, `randomBytes`) uses
  Node built-ins rather than third-party packages.

## 3. Information Disclosure

- No internal hostnames, RFC 1918 addresses, or private URLs anywhere in
  source or docs (`JWT_ISSUER` default is a clearly fictional `.local`).
- No commented-out credentials, TODO-with-secrets, or debug endpoints.
- Runtime disclosure controls (verified by the smoke suite): stack traces
  never leave the server; JSON parser errors are rewritten; `X-Powered-By`
  disabled; login failures are uniform; 401s carry no reason detail.
- Logs contain field NAMES on profile updates, never values; passwords and
  tokens are never logged (peppered digests only in the database).

## 4. Supply Chain Security

**Finding (remediated in this commit): floating caret ranges.**
`package.json` originally used `^` ranges, meaning a compromised future
minor/patch release of any dependency would be pulled in automatically on
a fresh install.

Remediation applied:
- All 9 dependencies are now **pinned to exact versions** in `package.json`.
- `package-lock.json` is committed and carries **`sha512` integrity hashes
  for all 150 resolved packages** — installs verify content, not just
  version numbers, which is the npm equivalent of hash-pinning.

Remaining recommendations for CI/CD (not representable in the repo itself):
- Install with `npm ci` (fails on any lockfile drift) — never `npm install` — in CI.
- Enable Dependabot/Renovate so pinning doesn't become staleness, and
  GitHub secret-scanning push protection on the repository.
- Consider `npm config set ignore-scripts true` in CI plus an explicit
  allowlist for `better-sqlite3`'s install script.

## Verdict

**APPROVED for commit to a public repository** with the version-pinning
remediation applied. No sanitized rewrite of any file was required — no
secret, internal reference, or test credential needed removal.
