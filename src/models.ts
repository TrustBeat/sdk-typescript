/**
 * TrustBeat SDK — domain models and API response parsers.
 */

// ── Public types ──────────────────────────────────────────────────────────────

/** One step in a Merkle inclusion proof. */
export interface ProofStep {
  /** Hex-encoded SHA-256 hash of the sibling node. */
  sibling: string;
  /** Position of the sibling: "left" or "right". */
  side: "left" | "right";
}

/** Returned by anchor() / anchor_batch() — represents a pending or completed job. */
export interface AnchorJob {
  id: string;
  hash: string;
  hashAlgorithm: string;
  status: string;
  submittedAt: string;
  overage: boolean;
}

/** Full inclusion proof returned once anchoring is complete. */
export interface AnchorProof {
  id: string;
  hash: string;
  hashAlgorithm: string;
  batchId: string;
  leafIndex: number;
  merkleRoot: string;
  proofPath: ProofStep[];
  /** Raw DER-encoded RFC 3161 TimeStampToken bytes. */
  token: Uint8Array;
  tokenFormat: string;
  tsaSerial: string;
  provider: string;
  anchoredAt: string;
  clientRef: string | null;
  description: string | null;
}

/** Returned by anchorBatch() — groups all submitted items under one submission_id. */
export interface BatchSubmission {
  submissionId: string;
  items: AnchorJob[];
}

/** Returned by getBatchStatus(). */
export interface BatchStatus {
  submissionId: string;
  total: number;
  anchored: number;
  pending: number;
}

// ── AI Act Audit models ───────────────────────────────────────────────────────

/** Time window of a single AI inference call. */
export interface AiTimeEnvelope {
  startedAt: string;    // ISO 8601 — when inference started
  completedAt: string;  // ISO 8601 — when inference completed
}

/**
 * Metadata describing an AI decision for EU AI Act Article 12 anchoring.
 * Only the required fields must be provided; optional fields are recommended
 * for auditor-ready records.
 */
export interface AiDecisionMetadata {
  /** Model identifier, e.g. "claude-3-5-sonnet-20241022". */
  modelId: string;
  /** AI system name, e.g. "cv-screening-v2". */
  systemName: string;
  /** AI Act Annex III risk category. */
  riskCategory: string;
  /** Type of decision: "classification", "ranking", "recommendation", etc. */
  decisionType: string;
  /** Whether human oversight per AI Act Article 14 was in place. */
  humanOversight: boolean;
  timeEnvelope: AiTimeEnvelope;
  modelVersion?: string;
  operatorId?: string;
  /** Deployment environment: "production", "staging", "testing". */
  deploymentEnv?: string;
  /** Operator's own case/record ID — links proof to a specific decision (Art. 12 traceability). */
  externalRef?: string;
  /** Semantic result of the decision, e.g. "rejected". No PII stored. */
  decisionOutcome?: string;
  /** SHA-256 hex of the deployed model weights/checkpoint. */
  modelArtifactHash?: string;
  /** Category of data subject, e.g. "job_applicant". */
  dataSubjectCategory?: string;
}

/** Returned immediately (202) when an AI decision is enqueued for anchoring. */
export interface AiDecisionJob {
  id: string;
  inputHash: string;
  outputHash: string;
  /** SHA-256(input_bytes ‖ output_bytes ‖ UTF-8(JCS(metadata))) */
  combinedHash: string;
  status: string;      // "pending"
  submittedAt: string; // ISO 8601
  overage: boolean;
}

/**
 * Verification result returned once the AI decision has been anchored.
 * verificationStatus is "VERIFIED" when the Merkle proof is valid and
 * the combined hash matches.
 */
export interface AiDecisionProof {
  id: string;
  inputHash: string;
  outputHash: string;
  combinedHash: string;
  metadata: AiDecisionMetadata;
  verificationStatus: "VERIFIED" | "FAILED";
  anchoredAt: string | null;
  proof: AnchorProof | null;
}

// ── Parsers ───────────────────────────────────────────────────────────────────

function b64ToUint8Array(b64: string): Uint8Array {
  return Buffer.from(b64, "base64");
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseAnchorJob(data: any): AnchorJob {
  return {
    id: data.id,
    hash: data.hash,
    hashAlgorithm: data.hash_algorithm,
    status: data.status,
    submittedAt: data.submitted_at,
    overage: data.overage ?? false,
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseProof(data: any): AnchorProof {
  return {
    id: data.id,
    hash: data.hash,
    hashAlgorithm: data.hash_algorithm,
    batchId: data.batch_id,
    leafIndex: data.leaf_index,
    merkleRoot: data.merkle_root,
    proofPath: (data.proof_path ?? []).map(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (s: any): ProofStep => ({ sibling: s.sibling, side: s.side })
    ),
    token: b64ToUint8Array(data.token),
    tokenFormat: data.token_format,
    tsaSerial: data.tsa_serial,
    provider: data.provider,
    anchoredAt: data.anchored_at,
    clientRef: data.client_ref ?? null,
    description: data.description ?? null,
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseBatchSubmission(data: any): BatchSubmission {
  return {
    submissionId: data.submission_id,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    items: (data.accepted ?? []).map((item: any) => parseAnchorJob(item)),
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseBatchStatus(data: any): BatchStatus {
  return {
    submissionId: data.submission_id,
    total:    data.total,
    anchored: data.anchored,
    pending:  data.pending,
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseAiDecisionJob(data: any): AiDecisionJob {
  return {
    id:           data.id,
    inputHash:    data.input_hash,
    outputHash:   data.output_hash,
    combinedHash: data.combined_hash,
    status:       data.status,
    submittedAt:  data.submitted_at,
    overage:      data.overage ?? false,
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseAiDecisionProof(data: any): AiDecisionProof {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const m = data.metadata as any;
  const meta: AiDecisionMetadata = {
    modelId:        m.model_id,
    systemName:     m.system_name,
    riskCategory:   m.risk_category,
    decisionType:   m.decision_type,
    humanOversight: m.human_oversight,
    timeEnvelope: {
      startedAt:   m.time_envelope.started_at,
      completedAt: m.time_envelope.completed_at,
    },
    modelVersion:        m.model_version         ?? undefined,
    operatorId:          m.operator_id           ?? undefined,
    deploymentEnv:       m.deployment_env        ?? undefined,
    externalRef:         m.external_ref          ?? undefined,
    decisionOutcome:     m.decision_outcome      ?? undefined,
    modelArtifactHash:   m.model_artifact_hash   ?? undefined,
    dataSubjectCategory: m.data_subject_category ?? undefined,
  };
  return {
    id:                 data.id,
    inputHash:          data.input_hash,
    outputHash:         data.output_hash,
    combinedHash:       data.combined_hash,
    metadata:           meta,
    verificationStatus: data.verification_status,
    anchoredAt:         data.anchored_at ?? null,
    proof:              data.proof ? parseProof(data.proof) : null,
  };
}

/** Returns true if data looks like an AnchorProof (has proofPath / merkleRoot). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function looksLikeProof(data: any): boolean {
  return data && typeof data.merkle_root === "string";
}

// ── Verification types ────────────────────────────────────────────────────────

export type SignatureVerdict =
  | "QUALIFIED_VALID" | "ADVANCED_VALID" | "VALID_NO_TIMESTAMP"
  | "REVOKED" | "EXPIRED_AT_SIGNING" | "CHAIN_BROKEN" | "TAMPERED" | "INVALID";

export interface SignatureDetail {
  index: number;
  signerName:       string | null;
  signerEmail:      string | null;
  signingTime:      string | null;
  certSerial:       string | null;
  certFingerprint:  string | null;
  certIssuer:       string | null;
  qualified:        boolean;
  onEutl:           boolean;
  qscd:             boolean;
  revocationStatus: string;
  revocationTime:   string | null;
  ocspResponse:     string | null;
  signatureLevel:   string;
  timestampPresent: boolean;
  timestampSerial:  string | null;
  verdict:          SignatureVerdict;
}

export interface VerificationReport {
  verdict:      SignatureVerdict;
  signatures:   SignatureDetail[];
  documentHash: string;
  checkedAt:    string;
  eutlVersion:  string | null;
  trackingId:   string | null;
}

export interface VerificationJob {
  trackingId:   string;
  documentHash: string;
  status:       "pending";
  submittedAt:  string;
}

export interface CertificateValidationResult {
  subject:          string;
  issuer:           string;
  serial:           string;
  notBefore:        string;
  notAfter:         string;
  qualified:        boolean;
  onEutl:           boolean;
  qscd:             boolean;
  revocationStatus: string;
  revocationTime:   string | null;
  keyUsage:         string[];
  valid:            boolean;
  validatedAt:      string;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseSignatureDetail(d: any): SignatureDetail {
  return {
    index:            d.index,
    signerName:       d.signer_name      ?? null,
    signerEmail:      d.signer_email     ?? null,
    signingTime:      d.signing_time     ?? null,
    certSerial:       d.cert_serial      ?? null,
    certFingerprint:  d.cert_fingerprint ?? null,
    certIssuer:       d.cert_issuer      ?? null,
    qualified:        d.qualified,
    onEutl:           d.on_eutl,
    qscd:             d.qscd,
    revocationStatus: d.revocation_status,
    revocationTime:   d.revocation_time  ?? null,
    ocspResponse:     d.ocsp_response    ?? null,
    signatureLevel:   d.signature_level,
    timestampPresent: d.timestamp_present,
    timestampSerial:  d.timestamp_serial ?? null,
    verdict:          d.verdict,
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseVerificationReport(d: any): VerificationReport {
  return {
    verdict:      d.verdict,
    signatures:   (d.signatures ?? []).map(parseSignatureDetail),
    documentHash: d.document_hash,
    checkedAt:    d.checked_at,
    eutlVersion:  d.eutl_version  ?? null,
    trackingId:   d.tracking_id   ?? null,
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseVerificationJob(d: any): VerificationJob {
  return {
    trackingId:   d.tracking_id,
    documentHash: d.document_hash,
    status:       d.status,
    submittedAt:  d.submitted_at,
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseCertValidationResult(d: any): CertificateValidationResult {
  return {
    subject:          d.subject,
    issuer:           d.issuer,
    serial:           d.serial,
    notBefore:        d.not_before,
    notAfter:         d.not_after,
    qualified:        d.qualified,
    onEutl:           d.on_eutl,
    qscd:             d.qscd,
    revocationStatus: d.revocation_status,
    revocationTime:   d.revocation_time ?? null,
    keyUsage:         d.key_usage        ?? [],
    valid:            d.valid,
    validatedAt:      d.validated_at,
  };
}

// ── Audit Trail ───────────────────────────────────────────────────────────────

/** One step in an audit event Merkle inclusion proof. */
export interface AuditProofStep {
  sibling: string;   // hex-encoded sibling hash
  side: "left" | "right";
}

/** A single audit event as returned by the list endpoint. */
export interface AuditEvent {
  eventId:       string;
  trailCategory: string;
  actor:         string;
  action:        string;
  ts:            string;         // ISO 8601 — when the event occurred
  receivedAt:    string;         // ISO 8601 — when TrustBeat received it
  anchored:      boolean;
  system:        string | null;
  resource:      string | null;
}

/** Full Merkle inclusion proof for an anchored audit event. */
export interface AuditEventProof {
  eventId:       string;
  canonicalHash: string;
  batchId:       string;
  leafIndex:     number;
  merklePath:    AuditProofStep[];
  anchoredAt:    string;         // ISO 8601
}

/** Returned immediately (202) when an export job is created. */
export interface AuditExportJob {
  jobId:       string;
  status:      "pending" | "processing" | "ready" | "failed";
  eventCount?: number;
  error?:      string;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseAuditProofStep(d: any): AuditProofStep {
  return { sibling: d.sibling, side: d.side };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseAuditEvent(d: any): AuditEvent {
  return {
    eventId:       d.event_id,
    trailCategory: d.trail_category,
    actor:         d.actor,
    action:        d.action,
    ts:            d.ts,
    receivedAt:    d.received_at,
    anchored:      d.anchored,
    system:        d.system   ?? null,
    resource:      d.resource ?? null,
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseAuditEventProof(d: any): AuditEventProof {
  return {
    eventId:       d.event_id,
    canonicalHash: d.canonical_hash,
    batchId:       d.batch_id,
    leafIndex:     d.leaf_index,
    merklePath:    (d.merkle_path ?? []).map(parseAuditProofStep),
    anchoredAt:    d.anchored_at,
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseAuditExportJob(d: any): AuditExportJob {
  return {
    jobId:       d.job_id,
    status:      d.status,
    eventCount:  d.event_count,
    error:       d.error,
  };
}

// ── Tamper-Evident Logs (NIS2) ────────────────────────────────────────────────

/** Identifies the log source being anchored. */
export interface LogSource {
  /** URI identifying the log source (file path, S3 URI, syslog identifier, etc.). */
  uri: string;
  /** Human-readable name for the log source. */
  name?: string;
  /** Size of the log file/stream in bytes. */
  sizeBytes?: number;
}

/** Time window covered by the anchored log. */
export interface LogTimeEnvelope {
  startAt: string; // ISO 8601
  endAt: string;   // ISO 8601
}

/** Identity of the system that emitted the log (all fields optional). */
export interface LogSourceIdentity {
  systemUuid?: string;
  cloudInstanceId?: string;
  hostname?: string;
  serviceName?: string;
  tenantId?: string;
}

/**
 * Metadata sealed alongside a log hash for NIS2 Article 21 anchoring.
 * The server computes combined_hash = SHA-256(log_hash_bytes ‖ UTF-8(JCS(metadata))),
 * binding this context into the Merkle leaf.
 */
export interface LogMetadata {
  logSource: LogSource;
  sourceIdentity: LogSourceIdentity;
  timeEnvelope?: LogTimeEnvelope;
}

/** Returned immediately (202) when a log hash is enqueued for anchoring. */
export interface LogAnchorJob {
  id: string;
  logHash: string;
  combinedHash: string;
  status: string;      // "pending"
  submittedAt: string; // ISO 8601
  overage: boolean;
  label: string | null;
}

/** Lightweight status of a log anchor submission. */
export interface LogStatus {
  id: string;
  status: "pending" | "anchored";
  submittedAt: string;
  anchoredAt: string | null;
}

/** A single log anchor submission as returned by the list endpoint. */
export interface LogAnchorListItem {
  id: string;
  logHash: string;
  status: "pending" | "anchored";
  submittedAt: string;
  logSourceUri: string;
  anchoredAt: string | null;
  serviceName: string | null;
  label: string | null;
}

/**
 * Verification result for an anchored log. verificationStatus is "VERIFIED" when
 * the Merkle proof is valid and the combined hash matches; proof is null otherwise.
 */
export interface LogProof {
  id: string;
  logHash: string;
  metadata: LogMetadata;
  combinedHash: string;
  verificationStatus: "VERIFIED" | "FAILED";
  archiveStampsCount: number;
  anchoredAt: string | null;
  proof: AnchorProof | null;
  failureReasons: string[] | null;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseLogAnchorJob(d: any): LogAnchorJob {
  return {
    id:           d.id,
    logHash:      d.log_hash,
    combinedHash: d.combined_hash,
    status:       d.status,
    submittedAt:  d.submitted_at,
    overage:      d.overage ?? false,
    label:        d.label ?? null,
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseLogStatus(d: any): LogStatus {
  return {
    id:          d.id,
    status:      d.status,
    submittedAt: d.submitted_at,
    anchoredAt:  d.anchored_at ?? null,
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseLogAnchorListItem(d: any): LogAnchorListItem {
  return {
    id:           d.id,
    logHash:      d.log_hash,
    status:       d.status,
    submittedAt:  d.submitted_at,
    logSourceUri: d.log_source_uri,
    anchoredAt:   d.anchored_at ?? null,
    serviceName:  d.service_name ?? null,
    label:        d.label ?? null,
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseLogMetadata(m: any): LogMetadata {
  const ident = m.source_identity ?? {};
  const te = m.time_envelope;
  return {
    logSource: {
      uri:       m.log_source.uri,
      name:      m.log_source.name ?? undefined,
      sizeBytes: m.log_source.size_bytes ?? undefined,
    },
    sourceIdentity: {
      systemUuid:      ident.system_uuid ?? undefined,
      cloudInstanceId: ident.cloud_instance_id ?? undefined,
      hostname:        ident.hostname ?? undefined,
      serviceName:     ident.service_name ?? undefined,
      tenantId:        ident.tenant_id ?? undefined,
    },
    timeEnvelope: te ? { startAt: te.start_at, endAt: te.end_at } : undefined,
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseLogProof(d: any): LogProof {
  return {
    id:                 d.id,
    logHash:            d.log_hash,
    metadata:           parseLogMetadata(d.metadata),
    combinedHash:       d.combined_hash,
    verificationStatus: d.verification_status,
    archiveStampsCount: d.archive_stamps_count ?? 0,
    anchoredAt:         d.anchored_at ?? null,
    proof:              d.proof ? parseProof(d.proof) : null,
    failureReasons:     d.failure_reasons ?? null,
  };
}

/** Serialize LogMetadata to the wire shape, omitting undefined optionals. */
export function logMetadataToJson(m: LogMetadata): Record<string, unknown> {
  const src: Record<string, unknown> = { uri: m.logSource.uri };
  if (m.logSource.name !== undefined)      src.name = m.logSource.name;
  if (m.logSource.sizeBytes !== undefined) src.size_bytes = m.logSource.sizeBytes;

  const ident: Record<string, unknown> = {};
  const id = m.sourceIdentity;
  if (id.systemUuid !== undefined)      ident.system_uuid = id.systemUuid;
  if (id.cloudInstanceId !== undefined) ident.cloud_instance_id = id.cloudInstanceId;
  if (id.hostname !== undefined)        ident.hostname = id.hostname;
  if (id.serviceName !== undefined)     ident.service_name = id.serviceName;
  if (id.tenantId !== undefined)        ident.tenant_id = id.tenantId;

  const out: Record<string, unknown> = { log_source: src, source_identity: ident };
  if (m.timeEnvelope !== undefined) {
    out.time_envelope = { start_at: m.timeEnvelope.startAt, end_at: m.timeEnvelope.endAt };
  }
  return out;
}
