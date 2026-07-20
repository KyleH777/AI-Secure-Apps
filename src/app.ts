import express from "express";
import { config } from "./config.js";
import { AppError } from "./errors.js";
import { strictCors } from "./middleware/cors.js";
import { errorHandler } from "./middleware/errorHandler.js";
import { rateLimit } from "./middleware/rateLimit.js";
import { requestId } from "./middleware/requestId.js";
import { securityHeaders } from "./middleware/securityHeaders.js";
import { profileRouter } from "./routes/profile.js";

export function createApp(): express.Express {
  const app = express();

  // SECURITY: don't advertise the framework (server fingerprinting).
  app.disable("x-powered-by");

  // SECURITY: trust exactly one reverse-proxy hop so req.ip is the real
  // client for rate limiting. `true` would let clients spoof
  // X-Forwarded-For and mint fresh rate-limit buckets at will.
  app.set("trust proxy", 1);

  app.use(requestId);
  app.use(securityHeaders);
  app.use(strictCors);

  // SECURITY (resource consumption): strict JSON-only parsing with a hard
  // size cap. Wrong content-type or oversized bodies fail before any
  // handler logic runs.
  app.use(express.json({ limit: config.maxJsonBodyBytes, type: "application/json" }));

  // Unauthenticated liveness probe — rate-limited per IP.
  app.get("/healthz", rateLimit, (_req, res) => {
    res.json({ status: "ok" });
  });

  app.use("/api/v1", profileRouter);

  // Uniform 404 for unknown routes, same envelope as every other error.
  app.use((_req, _res, next) => {
    next(new AppError("not_found", "Resource not found."));
  });

  app.use(errorHandler);
  return app;
}
