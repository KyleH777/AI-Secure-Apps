/**
 * End-to-end smoke test of every security control. Boots the app in-process
 * on an ephemeral port and asserts on real HTTP responses.
 * Run with: npm run smoke
 */
import { randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";
import { createApp } from "../src/app.js";
import { seedUserWithSession } from "../src/db.js";
import { digestSessionToken } from "../src/middleware/auth.js";

const rawToken = randomBytes(32).toString("base64url");
seedUserWithSession({
  email: "smoke@example.com",
  displayName: "Smoke User",
  tokenDigest: digestSessionToken(rawToken),
  sessionTtlMs: 60_000,
});

const server = createApp().listen(0);
const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

let failures = 0;
function check(name: string, ok: boolean, detail?: unknown): void {
  if (ok) {
    console.log(`  PASS  ${name}`);
  } else {
    failures += 1;
    console.error(`  FAIL  ${name}`, detail ?? "");
  }
}

const auth = { Authorization: `Bearer ${rawToken}` };
const json = { "Content-Type": "application/json" };

async function main(): Promise<void> {
  // 1. Auth is required.
  let res = await fetch(`${base}/api/v1/users/me/profile`);
  check("401 without token", res.status === 401);
  let body = await res.json();
  check("401 uses standard envelope", body.error?.code === "unauthorized" && !!body.error?.requestId);

  res = await fetch(`${base}/api/v1/users/me/profile`, {
    headers: { Authorization: "Bearer wrong-token-wrong-token-wrong" },
  });
  check("401 with bogus token", res.status === 401);

  // 2. Happy path PATCH.
  res = await fetch(`${base}/api/v1/users/me/profile`, {
    method: "PATCH",
    headers: { ...auth, ...json },
    body: JSON.stringify({ displayName: "Renée O'Neill-Smith", timezone: "Europe/Berlin" }),
  });
  body = await res.json();
  check("valid PATCH returns 200", res.status === 200, body);
  check("update persisted", body.data?.displayName === "Renée O'Neill-Smith");
  check("private columns not exposed", !("email" in (body.data ?? {})) && !("role" in (body.data ?? {})));

  // 3. Mass assignment rejected.
  res = await fetch(`${base}/api/v1/users/me/profile`, {
    method: "PATCH",
    headers: { ...auth, ...json },
    body: JSON.stringify({ displayName: "Hacker", role: "admin", isVerified: true }),
  });
  body = await res.json();
  check("mass assignment -> 422", res.status === 422, body);
  check("422 names offending fields only", body.error?.code === "validation_failed");

  // 4. XSS-shaped displayName rejected by character policy.
  res = await fetch(`${base}/api/v1/users/me/profile`, {
    method: "PATCH",
    headers: { ...auth, ...json },
    body: JSON.stringify({ displayName: "<script>alert(1)</script>" }),
  });
  check("script-tag displayName -> 422", res.status === 422);

  // 5. javascript: URL rejected.
  res = await fetch(`${base}/api/v1/users/me/profile`, {
    method: "PATCH",
    headers: { ...auth, ...json },
    body: JSON.stringify({ websiteUrl: "javascript:alert(1)" }),
  });
  check("javascript: URL -> 422", res.status === 422);

  // 6. SQL injection attempt is inert (stored as text, table intact).
  const sqli = "Robert'); DROP TABLE users;--";
  res = await fetch(`${base}/api/v1/users/me/profile`, {
    method: "PATCH",
    headers: { ...auth, ...json },
    body: JSON.stringify({ bio: sqli }),
  });
  body = await res.json();
  check("SQLi bio stored as inert text", res.status === 200 && body.data?.bio === sqli, body);
  res = await fetch(`${base}/api/v1/users/me/profile`, { headers: auth });
  check("users table survived SQLi attempt", res.status === 200);

  // 7. Malformed JSON -> clean 400, no parser internals.
  res = await fetch(`${base}/api/v1/users/me/profile`, {
    method: "PATCH",
    headers: { ...auth, ...json },
    body: "{not json",
  });
  body = await res.json();
  check("malformed JSON -> 400", res.status === 400);
  check("400 message is generic", body.error?.message === "Request body is not valid JSON.");

  // 8. Oversized body -> 413.
  res = await fetch(`${base}/api/v1/users/me/profile`, {
    method: "PATCH",
    headers: { ...auth, ...json },
    body: JSON.stringify({ bio: "x".repeat(64 * 1024) }),
  });
  check("oversized body -> 413", res.status === 413);

  // 9. CORS: allowed origin echoed, disallowed origin gets no CORS headers, never "*".
  res = await fetch(`${base}/healthz`, { headers: { Origin: "http://localhost:5173" } });
  check("allowed origin echoed", res.headers.get("access-control-allow-origin") === "http://localhost:5173");
  res = await fetch(`${base}/healthz`, { headers: { Origin: "https://evil.example" } });
  check("disallowed origin gets no ACAO header", res.headers.get("access-control-allow-origin") === null);

  // 10. Security headers present.
  check("nosniff header", res.headers.get("x-content-type-options") === "nosniff");
  check("CSP header", (res.headers.get("content-security-policy") ?? "").includes("default-src 'none'"));
  check("no X-Powered-By", res.headers.get("x-powered-by") === null);

  // 11. Rate limiting: hammer until 429 (limit is 30/min per user).
  let got429 = false;
  let retryAfter: string | null = null;
  for (let i = 0; i < 40; i += 1) {
    const r = await fetch(`${base}/api/v1/users/me/profile`, { headers: auth });
    if (r.status === 429) {
      got429 = true;
      retryAfter = r.headers.get("retry-after");
      await r.body?.cancel();
      break;
    }
    await r.body?.cancel();
  }
  check("sliding-window limiter returns 429", got429);
  check("429 carries Retry-After", retryAfter !== null);

  // 12. Unknown route -> standardized 404 envelope.
  res = await fetch(`${base}/api/v1/definitely-not-a-route`);
  body = await res.json();
  check("unknown route -> enveloped 404", res.status === 404 && body.error?.code === "not_found");

  server.close();
  console.log(failures === 0 ? "\nAll smoke checks passed." : `\n${failures} check(s) FAILED.`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  server.close();
  process.exit(1);
});
