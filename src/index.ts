/**
 * TrustBeat SDK — main entry point.
 *
 * Zero runtime dependencies.
 * Requires Node 18+ (globalThis.fetch, crypto.subtle) or a modern browser.
 */

export { TrustBeat } from "./client.js";
export type { TrustBeatOptions, AnchorOptions, AnchorWaitOptions } from "./client.js";

export type {
  AnchorJob, AnchorProof, ProofStep,
  SignatureDetail, VerificationReport, VerificationJob, CertificateValidationResult,
  SignatureVerdict,
  AuditProofStep, AuditEvent, AuditEventProof, AuditExportJob,
  LogSource, LogTimeEnvelope, LogSourceIdentity, LogMetadata,
  LogAnchorJob, LogStatus, LogAnchorListItem, LogProof,
} from "./models.js";

export {
  TrustBeatError,
  AuthError,
  NotFoundError,
  QuotaError,
  RateLimitError,
  VerificationError,
  UnsupportedAlgorithmError,
  IncompleteProofError,
} from "./exceptions.js";

export { verifyProof, verifyAuditEventProof } from "./verify.js";
export { LEGACY_SHA256, RFC6962_SHA256 } from "./models.js";
export { hashBuffer, hashString } from "./hash.js";
export { verifyWebhookSignature } from "./webhook.js";
export type { WebhookVerifyOptions } from "./webhook.js";
