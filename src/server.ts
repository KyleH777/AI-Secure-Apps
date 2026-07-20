import { randomBytes } from "node:crypto";
import { createApp } from "./app.js";
import { config } from "./config.js";
import { seedUserWithSession } from "./db.js";
import { logger } from "./logger.js";
import { digestSessionToken } from "./middleware/auth.js";

const app = createApp();

/**
 * Dev convenience: seed one user + session so the API is testable
 * immediately. The raw token is generated fresh per boot (never a
 * hardcoded credential) and printed to the local console only.
 * Guarded out of production builds entirely.
 */
if (!config.isProduction) {
  const rawToken = randomBytes(32).toString("base64url");
  seedUserWithSession({
    email: "dev@example.com",
    displayName: "Dev User",
    tokenDigest: digestSessionToken(rawToken),
    sessionTtlMs: 60 * 60 * 1000, // 1 hour — short-lived even in dev (AISDP #3).
  });
  logger.info("dev_session_seeded", { hint: `Authorization: Bearer ${rawToken}` });
}

app.listen(config.port, () => {
  logger.info("server_started", { port: config.port, production: config.isProduction });
});
