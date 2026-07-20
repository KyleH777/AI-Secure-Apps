/**
 * Standardized application error type + JSON error envelope.
 *
 * SECURITY (Error Handling / OWASP A09 Security Logging & Monitoring):
 * Every error leaving this API goes through one envelope shape:
 *
 *   { "error": { "code": "...", "message": "...", "requestId": "..." } }
 *
 * `message` is always an operator-authored, client-safe string. Stack traces,
 * driver errors, and internal exception messages never reach the response —
 * they are logged server-side, keyed by requestId, so support can correlate
 * a user report with the full internal detail.
 */

export type ErrorCode =
  | "bad_request"
  | "validation_failed"
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "payload_too_large"
  | "rate_limited"
  | "internal_error";

const STATUS_BY_CODE: Record<ErrorCode, number> = {
  bad_request: 400,
  validation_failed: 422,
  unauthorized: 401,
  forbidden: 403,
  not_found: 404,
  payload_too_large: 413,
  rate_limited: 429,
  internal_error: 500,
};

export class AppError extends Error {
  readonly code: ErrorCode;
  readonly status: number;
  /** Optional machine-readable detail that is SAFE to show clients (e.g. field-level validation issues). */
  readonly publicDetails: unknown;

  constructor(code: ErrorCode, clientSafeMessage: string, publicDetails?: unknown) {
    super(clientSafeMessage);
    this.code = code;
    this.status = STATUS_BY_CODE[code];
    this.publicDetails = publicDetails;
  }
}

export interface ErrorEnvelope {
  error: {
    code: ErrorCode;
    message: string;
    requestId: string;
    details?: unknown;
  };
}

export function toEnvelope(err: AppError, requestId: string): ErrorEnvelope {
  return {
    error: {
      code: err.code,
      message: err.message,
      requestId,
      ...(err.publicDetails !== undefined ? { details: err.publicDetails } : {}),
    },
  };
}
