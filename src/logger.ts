/**
 * Minimal structured JSON logger.
 *
 * SECURITY (log injection / OWASP A09): every log line is a single
 * JSON.stringify'd object — user-influenced values are serialized, never
 * concatenated raw, so embedded newlines or ANSI sequences cannot forge or
 * mangle log records. Never log tokens, passwords, or full request bodies.
 */
type LogFields = Record<string, unknown>;

function emit(level: "info" | "warn" | "error", event: string, fields: LogFields): void {
  const line = JSON.stringify({
    level,
    event,
    time: new Date().toISOString(),
    ...fields,
  });
  if (level === "error") process.stderr.write(line + "\n");
  else process.stdout.write(line + "\n");
}

export const logger = {
  info: (event: string, fields: LogFields = {}) => emit("info", event, fields),
  warn: (event: string, fields: LogFields = {}) => emit("warn", event, fields),
  error: (event: string, fields: LogFields = {}) => emit("error", event, fields),
};
