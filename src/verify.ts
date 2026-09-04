/**
 * Local Merkle inclusion proof verification.
 *
 * The fold depends on the construction the proof declares in `merkleAlgorithm`:
 *
 *   trustbeat-legacy-sha256 — leaf = your hash, parent = SHA-256(left || right)
 *   rfc6962-sha256          — leaf = SHA-256(0x00 || your hash),
 *                             parent = SHA-256(0x01 || left || right)
 *
 * In both, `side` gives the *sibling's* position:
 *   side="left"  → sibling is on the left  → hash over (sibling, current)
 *   side="right" → sibling is on the right → hash over (current, sibling)
 *
 * A proof with no `merkleAlgorithm` predates the field and is legacy.
 */

import { createHash, timingSafeEqual as nodeTSE } from "node:crypto";
import { AnchorProof, AuditEventProof, LEGACY_SHA256, RFC6962_SHA256 } from "./models.js";
import {
  IncompleteProofError,
  UnsupportedAlgorithmError,
  VerificationError,
} from "./exceptions.js";

/** algorithm → [leaf prefix, node prefix] */
const PREFIXES: Record<string, [Buffer, Buffer]> = {
  [LEGACY_SHA256]: [Buffer.alloc(0), Buffer.alloc(0)],
  [RFC6962_SHA256]: [Buffer.from([0x00]), Buffer.from([0x01])],
};

// ── Hex helpers ───────────────────────────────────────────────────────────────

function hexToBytes(hex: string, label: string): Buffer {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) {
    throw new VerificationError(`${label}: invalid hex string`);
  }
  return Buffer.from(hex, "hex");
}

// ── SHA-256 (synchronous via node:crypto) ─────────────────────────────────────

function sha256(data: Buffer): Buffer {
  return createHash("sha256").update(data).digest();
}

function concat(a: Buffer, b: Buffer): Buffer {
  return Buffer.concat([a, b]);
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Verify a Merkle inclusion proof locally (no network call).
 *
 * Returns `true` if the computed root matches `proof.merkleRoot`,
 * `false` if the proof is cryptographically invalid.
 * Throws `VerificationError` if input data is malformed, or
 * `UnsupportedAlgorithmError` if this SDK cannot compute the declared algorithm.
 */
export async function verifyProof(proof: AnchorProof): Promise<boolean> {
  const algorithm = proof.merkleAlgorithm || LEGACY_SHA256;
  const prefixes = PREFIXES[algorithm];
  if (!prefixes) {
    throw new UnsupportedAlgorithmError(
      `Unsupported merkleAlgorithm "${algorithm}". This SDK understands ` +
        `${Object.keys(PREFIXES).join(", ")}. Upgrade the SDK, or verify via the API.`
    );
  }
  const [leafPrefix, nodePrefix] = prefixes;

  // Decode leaf hash
  let current: Buffer;
  try {
    current = hexToBytes(proof.hash, "Invalid leaf hash");
  } catch {
    throw new VerificationError(`Invalid leaf hash: "${proof.hash}"`);
  }
  if (leafPrefix.length > 0) current = sha256(concat(leafPrefix, current));

  // Decode expected root
  let expectedRoot: Buffer;
  try {
    expectedRoot = hexToBytes(proof.merkleRoot, "Invalid merkle_root");
  } catch {
    throw new VerificationError(`Invalid merkle_root: "${proof.merkleRoot}"`);
  }

  // Walk the proof path
  for (const step of proof.proofPath) {
    let sibling: Buffer;
    try {
      sibling = hexToBytes(step.sibling, "Invalid sibling hex");
    } catch {
      throw new VerificationError(`Invalid sibling hex: "${step.sibling}"`);
    }

    if (step.side === "left") {
      // sibling is on the left: parent = hash(P || sibling || current)
      current = sha256(concat(nodePrefix, concat(sibling, current)));
    } else if (step.side === "right") {
      // sibling is on the right: parent = hash(P || current || sibling)
      current = sha256(concat(nodePrefix, concat(current, sibling)));
    } else {
      throw new VerificationError(`Unknown side: "${step.side}" — expected "left" or "right"`);
    }
  }

  // Constant-time comparison (both buffers must be same length)
  if (current.length !== expectedRoot.length) return false;
  return nodeTSE(current, expectedRoot);
}

/**
 * Verify an audit event's Merkle inclusion proof locally (no network call).
 *
 * The audit counterpart of `verifyProof`, for the shape that names the leaf
 * `canonicalHash` and the path `merklePath`.
 *
 * Returns `true` if valid, `false` if the computed root does not match.
 *
 * Throws `IncompleteProofError` when the proof carries no `merkleRoot`: servers
 * before API 1.46 did not send one, so there is nothing to fold against. That is
 * "cannot check", never "invalid". Throws `UnsupportedAlgorithmError` and
 * `VerificationError` on the same terms as `verifyProof`.
 */
export async function verifyAuditEventProof(proof: AuditEventProof): Promise<boolean> {
  if (!proof.merkleRoot) {
    throw new IncompleteProofError(
      "This audit event proof has no merkleRoot, so it cannot be folded locally. " +
        "The server that issued it predates API 1.46. Verify it server-side via the " +
        "API, or re-fetch it from an upgraded server."
    );
  }
  // Reuse the anchor fold: the two shapes differ only in field names.
  return verifyProof({
    hash:            proof.canonicalHash,
    merkleRoot:      proof.merkleRoot,
    proofPath:       proof.merklePath,
    merkleAlgorithm: proof.merkleAlgorithm,
  } as unknown as AnchorProof);
}
