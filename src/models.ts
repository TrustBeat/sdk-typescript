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

/** Returns true if data looks like an AnchorProof (has proofPath / merkleRoot). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function looksLikeProof(data: any): boolean {
  return data && typeof data.merkle_root === "string";
}
