/**
 * Local Merkle inclusion proof verification.
 *
 * Algorithm mirrors MerkleEngine.scala exactly:
 *   parent = SHA-256(left_child || right_child)
 *   side="left"  → sibling is on the left  → hash(sibling || current)
 *   side="right" → sibling is on the right → hash(current || sibling)
 *   Odd layers duplicate the last node.
 */

import { createHash, timingSafeEqual as nodeTSE } from "node:crypto";
import { AnchorProof } from "./models.js";
import { VerificationError } from "./exceptions.js";

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
 * Throws `VerificationError` if input data is malformed.
 */
export async function verifyProof(proof: AnchorProof): Promise<boolean> {
  // Decode leaf hash
  let current: Buffer;
  try {
    current = hexToBytes(proof.hash, "Invalid leaf hash");
  } catch {
    throw new VerificationError(`Invalid leaf hash: "${proof.hash}"`);
  }

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
      // sibling is on the left: parent = hash(sibling || current)
      current = sha256(concat(sibling, current));
    } else if (step.side === "right") {
      // sibling is on the right: parent = hash(current || sibling)
      current = sha256(concat(current, sibling));
    } else {
      throw new VerificationError(`Unknown side: "${step.side}" — expected "left" or "right"`);
    }
  }

  // Constant-time comparison (both buffers must be same length)
  if (current.length !== expectedRoot.length) return false;
  return nodeTSE(current, expectedRoot);
}
