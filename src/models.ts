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

/** Result of a direct timestamp() call (non-Merkle, single-hash). */
export interface TimestampResult {
  id: string;
  hash: string;
  hashAlgorithm: string;
  /** Raw DER-encoded RFC 3161 TimeStampToken bytes. */
  token: Uint8Array;
  tokenFormat: string;
  tsaSerial: string;
  provider: string;
  timestampedAt: string;
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
export function parseTimestamp(data: any): TimestampResult {
  return {
    id: data.id,
    hash: data.hash,
    hashAlgorithm: data.hash_algorithm,
    token: b64ToUint8Array(data.token),
    tokenFormat: data.token_format,
    tsaSerial: data.tsa_serial,
    provider: data.provider,
    timestampedAt: data.timestamped_at,
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
    modelVersion:  m.model_version ?? undefined,
    operatorId:    m.operator_id   ?? undefined,
    deploymentEnv: m.deployment_env ?? undefined,
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
