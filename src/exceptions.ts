/**
 * TrustBeat SDK — exception hierarchy.
 */

export class TrustBeatError extends Error {
  readonly status: number | undefined;
  readonly code: string | undefined;

  constructor(message: string, status?: number, code?: string) {
    super(message);
    this.name = "TrustBeatError";
    this.status = status;
    this.code = code;
  }
}

/** 401 — invalid or missing API key. */
export class AuthError extends TrustBeatError {
  constructor(message: string) {
    super(message, 401, "UNAUTHORIZED");
    this.name = "AuthError";
  }
}

/** 404 — tracking ID not found. */
export class NotFoundError extends TrustBeatError {
  constructor(message: string) {
    super(message, 404, "NOT_FOUND");
    this.name = "NotFoundError";
  }
}

/** 402 — monthly quota exceeded. */
export class QuotaError extends TrustBeatError {
  constructor(message: string) {
    super(message, 402, "QUOTA_EXCEEDED");
    this.name = "QuotaError";
  }
}

/** 429 — too many requests. */
export class RateLimitError extends TrustBeatError {
  constructor(message: string) {
    super(message, 429, "RATE_LIMITED");
    this.name = "RateLimitError";
  }
}

/** Raised when local Merkle proof verification encounters malformed data. */
export class VerificationError extends TrustBeatError {
  constructor(message: string) {
    super(message, undefined, "VERIFICATION_ERROR");
    this.name = "VerificationError";
  }
}
