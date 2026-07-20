import type { NextFunction, Request, Response } from "express";
import { AppError, toEnvelope } from "../errors.js";
import { logger } from "../logger.js";

/**
 * Central error handler — the ONLY place that turns errors into responses.
 *
 * SECURITY (Error Handling):
 * - Known AppErrors return their operator-authored, client-safe message.
 * - Anything else (driver errors, TypeErrors, bugs) becomes an opaque 500:
 *   "An unexpected error occurred." — no stack trace, no exception message,
 *   no class name, regardless of NODE_ENV. The full error is logged
 *   server-side keyed by requestId for debugging.
 * - Express's body-parser errors are mapped to clean 400/413s so malformed
 *   JSON can't leak parser internals ("Unexpected token ... in JSON").
 */
export function errorHandler(
  err: unknown,
  req: Request,
  res: Response,
  // Express identifies error middleware by arity — the 4th param must exist.
  _next: NextFunction,
): void {
  const requestId = req.requestId ?? "unknown";

  let appError: AppError;
  if (err instanceof AppError) {
    appError = err;
  } else if (isBodyParserError(err)) {
    appError =
      err.type === "entity.too.large"
        ? new AppError("payload_too_large", "Request body is too large.")
        : new AppError("bad_request", "Request body is not valid JSON.");
  } else {
    // Unexpected error: log everything internally, reveal nothing externally.
    logger.error("unhandled_error", {
      requestId,
      method: req.method,
      path: req.path,
      error: err instanceof Error ? { message: err.message, stack: err.stack } : String(err),
    });
    appError = new AppError("internal_error", "An unexpected error occurred.");
  }

  if (appError.status >= 500) {
    // 4xx are client mistakes; only 5xx indicate server problems worth paging on.
    logger.error("request_failed", { requestId, code: appError.code, status: appError.status });
  }

  res.status(appError.status).json(toEnvelope(appError, requestId));
}

interface BodyParserError {
  type: string;
  status?: number;
}

function isBodyParserError(err: unknown): err is BodyParserError {
  return (
    typeof err === "object" &&
    err !== null &&
    "type" in err &&
    typeof (err as { type: unknown }).type === "string"
  );
}
