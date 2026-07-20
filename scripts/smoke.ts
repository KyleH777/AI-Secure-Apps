/**
 * End-to-end smoke test of every security control. Boots the app in-process
 * on an ephemeral port and asserts on real HTTP responses.
 * Run with: npm run smoke
 */
import { randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";
import { createApp } from "../src/app.js";
import { hashPassword } from "../src/auth/passwords.js";
import { createUser } from "../src/db.js";

const email = "smoke@example.com";
const password = randomBytes(12).toString("base64url");
createUser({ email, displayName: "Smoke User", passwordHash: await hashPassword(password) });

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

const json = { "Content-Type": "application/json" };

function refreshCookieFrom(res: globalThis.Response): string | null {
  const setCookie = res.headers.getSetCookie().find((c) => c.startsWith("refresh_token="));
  if (!setCookie) return null;
  return setCookie.split(";")[0]?.split("=")[1] ?? null;
}

async function login(body: unknown): Promise<globalThis.Response> {
  return fetch(`${base}/api/v1/auth/login`, {
    method: "POST",
    headers: json,
    body: JSON.stringify(body),
  });
}

async function main(): Promise<void> {
  // ---- IAM: login ----
  let res = await login({ email, password: "definitely-wrong-password" });
  let body = await res.json();
  check("wrong password -> 401", res.status === 401);
  check("401 message is uniform", body.error?.message === "Invalid email or password.");

  res = await login({ email: "nobody@example.com", password: "irrelevant-pw" });
  body = await res.json();
  check("unknown email -> identical 401", res.status === 401 && body.error?.message === "Invalid email or password.");

  res = await login({ email, password, role: "admin" });
  check("extra fields on login -> 401 (strict schema)", res.status === 401);

  res = await login({ email, password });
  body = await res.json();
  check("valid login -> 200 with access token", res.status === 200 && typeof body.data?.accessToken === "string", body);
  check("expiresIn is 15 minutes", body.data?.expiresIn === 900);
  const accessToken = body.data.accessToken as string;

  const loginSetCookie = res.headers.getSetCookie().find((c) => c.startsWith("refresh_token=")) ?? "";
  check("refresh cookie is HttpOnly", /httponly/i.test(loginSetCookie), loginSetCookie);
  check("refresh cookie is SameSite=Strict", /samesite=strict/i.test(loginSetCookie));
  check("refresh cookie path-scoped to /api/v1/auth", /path=\/api\/v1\/auth/i.test(loginSetCookie));
  check("access token absent from cookies", !loginSetCookie.includes(accessToken));
  const refreshToken1 = refreshCookieFrom(res);
  check("refresh cookie present", refreshToken1 !== null);

  // ---- IAM: access-token verification ----
  const auth = { Authorization: `Bearer ${accessToken}` };
  res = await fetch(`${base}/api/v1/users/me/profile`, { headers: auth });
  check("JWT grants access to protected route", res.status === 200);

  res = await fetch(`${base}/api/v1/users/me/profile`);
  check("401 without token", res.status === 401);

  const [h, p] = accessToken.split(".");
  res = await fetch(`${base}/api/v1/users/me/profile`, {
    headers: { Authorization: `Bearer ${h}.${p}.${"A".repeat(43)}` },
  });
  check("tampered signature -> 401", res.status === 401);

  const noneHeader = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
  res = await fetch(`${base}/api/v1/users/me/profile`, {
    headers: { Authorization: `Bearer ${noneHeader}.${p}.x` },
  });
  check("alg:none token -> 401", res.status === 401);

  // ---- IAM: refresh rotation ----
  res = await fetch(`${base}/api/v1/auth/refresh`, {
    method: "POST",
    headers: { Cookie: `refresh_token=${refreshToken1}` },
  });
  body = await res.json();
  const refreshToken2 = refreshCookieFrom(res);
  check("refresh -> 200 with new access token", res.status === 200 && typeof body.data?.accessToken === "string");
  check("refresh token ROTATED (new value issued)", refreshToken2 !== null && refreshToken2 !== refreshToken1);

  // Reuse of the OLD (already-rotated) token = theft signal -> family revoked.
  res = await fetch(`${base}/api/v1/auth/refresh`, {
    method: "POST",
    headers: { Cookie: `refresh_token=${refreshToken1}` },
  });
  check("reused old refresh token -> 401", res.status === 401);

  res = await fetch(`${base}/api/v1/auth/refresh`, {
    method: "POST",
    headers: { Cookie: `refresh_token=${refreshToken2}` },
  });
  check("reuse detection revoked the WHOLE family", res.status === 401);

  // ---- IAM: logout revokes server-side ----
  res = await login({ email, password });
  body = await res.json();
  const refreshToken3 = refreshCookieFrom(res);
  check("re-login issues a fresh family", refreshToken3 !== null);

  res = await fetch(`${base}/api/v1/auth/logout`, {
    method: "POST",
    headers: { Cookie: `refresh_token=${refreshToken3}` },
  });
  check("logout -> 204", res.status === 204);
  check("logout clears cookie", /max-age=0/i.test(res.headers.getSetCookie().join(";")));

  res = await fetch(`${base}/api/v1/auth/refresh`, {
    method: "POST",
    headers: { Cookie: `refresh_token=${refreshToken3}` },
  });
  check("revoked (logged-out) refresh token -> 401", res.status === 401);

  // ---- Profile endpoint controls (regression) ----
  res = await fetch(`${base}/api/v1/users/me/profile`, {
    method: "PATCH",
    headers: { ...auth, ...json },
    body: JSON.stringify({ displayName: "Renée O'Neill-Smith", timezone: "Europe/Berlin" }),
  });
  body = await res.json();
  check("valid PATCH returns 200", res.status === 200, body);
  check("private columns not exposed", !("email" in (body.data ?? {})) && !("passwordHash" in (body.data ?? {})));

  res = await fetch(`${base}/api/v1/users/me/profile`, {
    method: "PATCH",
    headers: { ...auth, ...json },
    body: JSON.stringify({ displayName: "Hacker", role: "admin" }),
  });
  check("mass assignment -> 422", res.status === 422);

  res = await fetch(`${base}/api/v1/users/me/profile`, {
    method: "PATCH",
    headers: { ...auth, ...json },
    body: JSON.stringify({ displayName: "<script>alert(1)</script>" }),
  });
  check("script-tag displayName -> 422", res.status === 422);

  res = await fetch(`${base}/api/v1/users/me/profile`, {
    method: "PATCH",
    headers: { ...auth, ...json },
    body: JSON.stringify({ websiteUrl: "javascript:alert(1)" }),
  });
  check("javascript: URL -> 422", res.status === 422);

  const sqli = "Robert'); DROP TABLE users;--";
  res = await fetch(`${base}/api/v1/users/me/profile`, {
    method: "PATCH",
    headers: { ...auth, ...json },
    body: JSON.stringify({ bio: sqli }),
  });
  body = await res.json();
  check("SQLi bio stored as inert text", res.status === 200 && body.data?.bio === sqli, body);

  res = await fetch(`${base}/api/v1/users/me/profile`, {
    method: "PATCH",
    headers: { ...auth, ...json },
    body: "{not json",
  });
  body = await res.json();
  check("malformed JSON -> 400, generic message", res.status === 400 && body.error?.message === "Request body is not valid JSON.");

  res = await fetch(`${base}/api/v1/users/me/profile`, {
    method: "PATCH",
    headers: { ...auth, ...json },
    body: JSON.stringify({ bio: "x".repeat(64 * 1024) }),
  });
  check("oversized body -> 413", res.status === 413);

  // ---- CORS + headers ----
  res = await fetch(`${base}/healthz`, { headers: { Origin: "http://localhost:5173" } });
  check("allowed origin echoed", res.headers.get("access-control-allow-origin") === "http://localhost:5173");
  res = await fetch(`${base}/healthz`, { headers: { Origin: "https://evil.example" } });
  check("disallowed origin gets no ACAO header", res.headers.get("access-control-allow-origin") === null);
  check("nosniff header", res.headers.get("x-content-type-options") === "nosniff");
  check("CSP header", (res.headers.get("content-security-policy") ?? "").includes("default-src 'none'"));
  check("no X-Powered-By", res.headers.get("x-powered-by") === null);

  // ---- Rate limiting ----
  // Auth limiter: 10/min per IP -> the login attempts above plus a few more must trip it.
  let got429 = false;
  for (let i = 0; i < 12; i += 1) {
    const r = await login({ email, password: "wrong-password-x" });
    await r.body?.cancel();
    if (r.status === 429) {
      got429 = true;
      break;
    }
  }
  check("auth endpoints rate limited (tight per-IP budget)", got429);

  // API limiter: hammer the profile GET until 429 (30/min per user).
  got429 = false;
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
  check("sliding-window API limiter returns 429", got429);
  check("429 carries Retry-After", retryAfter !== null);

  // ---- Error envelope ----
  res = await fetch(`${base}/api/v1/definitely-not-a-route`);
  body = await res.json();
  check("unknown route -> enveloped 404", res.status === 404 && body.error?.code === "not_found" && !!body.error?.requestId);

  server.close();
  console.log(failures === 0 ? "\nAll smoke checks passed." : `\n${failures} check(s) FAILED.`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  server.close();
  process.exit(1);
});
