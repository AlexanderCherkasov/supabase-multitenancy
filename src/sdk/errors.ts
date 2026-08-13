export const ERROR_CODES = [
  "UNAUTHENTICATED",
  "FORBIDDEN",
  "NOT_FOUND",
  "CONFLICT",
  "INVALID_INPUT",
  "TOKEN_INVALID",
  "TOKEN_EXPIRED",
  "TOKEN_REVOKED",
  "TOKEN_ACCEPTED",
  "EMAIL_MISMATCH",
  "LAST_OWNER",
  "ROLE_ESCALATION",
  "VERSION_MISMATCH",
  "UNKNOWN",
] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

export class MultitenancyError extends Error {
  code: ErrorCode;
  cause?: unknown;
  constructor(code: ErrorCode, message: string, cause?: unknown) {
    super(message);
    this.name = "MultitenancyError";
    this.code = code;
    this.cause = cause;
  }
}

export function mapPostgresError(err: { message?: string; code?: string }): MultitenancyError {
  if (err instanceof MultitenancyError) return err;
  const msg = err.message ?? "Unknown error";
  const pgCode = err.code ?? "";
  if (msg.includes("ROLE_ESCALATION")) return new MultitenancyError("ROLE_ESCALATION", msg, err);
  if (msg.includes("EMAIL_MISMATCH")) return new MultitenancyError("EMAIL_MISMATCH", msg, err);
  if (msg.includes("FORBIDDEN") || pgCode === "42501") return new MultitenancyError("FORBIDDEN", msg, err);
  if (msg.includes("NOT_FOUND") || pgCode === "42704") return new MultitenancyError("NOT_FOUND", msg, err);
  if (msg.includes("CONFLICT") || pgCode === "23505") return new MultitenancyError("CONFLICT", msg, err);
  if (msg.includes("INVALID_INPUT") || pgCode === "22P02") return new MultitenancyError("INVALID_INPUT", msg, err);
  if (msg.includes("TOKEN_REVOKED")) return new MultitenancyError("TOKEN_REVOKED", msg, err);
  if (msg.includes("TOKEN_EXPIRED")) return new MultitenancyError("TOKEN_EXPIRED", msg, err);
  if (msg.includes("TOKEN_ACCEPTED")) return new MultitenancyError("TOKEN_ACCEPTED", msg, err);
  if (msg.includes("TOKEN_INVALID") || pgCode === "28000") return new MultitenancyError("TOKEN_INVALID", msg, err);
  if (msg.includes("UNAUTHENTICATED")) return new MultitenancyError("UNAUTHENTICATED", msg, err);
  if (msg.includes("LAST_OWNER")) return new MultitenancyError("LAST_OWNER", msg, err);
  return new MultitenancyError("UNKNOWN", msg, err);
}

export function assertApiVersion(data: { api_version?: number }): void {
  if (data.api_version !== 1) {
    throw new MultitenancyError("VERSION_MISMATCH", `Unsupported api_version ${data.api_version}, expected 1`);
  }
}
