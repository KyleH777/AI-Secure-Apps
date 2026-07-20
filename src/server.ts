import { randomBytes } from "node:crypto";
import { createApp } from "./app.js";
import { hashPassword } from "./auth/passwords.js";
import { config } from "./config.js";
import { createUser } from "./db.js";
import { logger } from "./logger.js";

const app = createApp();

/**
 * Dev convenience: seed one user so the login flow is testable immediately.
 * The password is generated fresh per boot (never a hardcoded credential)
 * and printed to the local console only. Guarded out of production entirely.
 */
async function seedDevUser(): Promise<void> {
  const password = randomBytes(12).toString("base64url");
  createUser({
    email: "dev@example.com",
    displayName: "Dev User",
    passwordHash: await hashPassword(password),
  });
  logger.info("dev_user_seeded", {
    hint: `POST /api/v1/auth/login {"email":"dev@example.com","password":"${password}"}`,
  });
}

if (!config.isProduction) {
  await seedDevUser();
}

app.listen(config.port, () => {
  logger.info("server_started", { port: config.port, production: config.isProduction });
});
