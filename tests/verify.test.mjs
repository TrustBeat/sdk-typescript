/**
 * Unit tests for local Merkle proof verification.
 *
 * Uses node:test + node:assert (Node 18+ built-in, zero dependencies).
 * Mirrors the algorithm from MerkleEngine.scala:
 *   parent = SHA-256(left_child || right_child)
 *   side="left"  → sibling on the left  → hash(sibling || current)
 *   side="right" → sibling on the right → hash(current || sibling)
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import { verifyProof, VerificationError } from "../dist/index.js";

// ── Helpers ───────────────────────────────────────────────────────────────────

function sha256(data) {
  return createHash("sha256").update(data).digest();
}

function combine(a, b) {
  return sha256(Buffer.concat([a, b]));
}

function toHex(bytes) {
  return bytes.toString("hex");
}

function makeProof(leaf, path, root) {
  return {
    id: "test-id",
    hash: toHex(leaf),
    hashAlgorithm: "sha256",
    batchId: "batch-1",
    leafIndex: 0,
    merkleRoot: toHex(root),
    proofPath: path,
    token: new Uint8Array(0),
    tokenFormat: "rfc3161",
    tsaSerial: "0",
    provider: "test",
    anchoredAt: "2026-01-01T00:00:00Z",
    clientRef: null,
    description: null,
  };
}

// ── 4-leaf tree test vectors ──────────────────────────────────────────────────
//
//  leaves:  L0   L1   L2   L3
//  layer1:  N01=H(L0,L1)   N23=H(L2,L3)
//  root:    R  =H(N01,N23)

const L0 = sha256(Buffer.from("leaf0"));
const L1 = sha256(Buffer.from("leaf1"));
const L2 = sha256(Buffer.from("leaf2"));
const L3 = sha256(Buffer.from("leaf3"));
const N01 = combine(L0, L1);
const N23 = combine(L2, L3);
const ROOT4 = combine(N01, N23);

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("4-leaf Merkle tree", () => {

  it("leaf0 proof is valid", async () => {
    const path = [
      { sibling: toHex(L1),  side: "right" },
      { sibling: toHex(N23), side: "right" },
    ];
    assert.equal(await verifyProof(makeProof(L0, path, ROOT4)), true);
  });

  it("leaf1 proof is valid", async () => {
    const path = [
      { sibling: toHex(L0),  side: "left" },
      { sibling: toHex(N23), side: "right" },
    ];
    assert.equal(await verifyProof(makeProof(L1, path, ROOT4)), true);
  });

  it("leaf2 proof is valid", async () => {
    const path = [
      { sibling: toHex(L3),  side: "right" },
      { sibling: toHex(N01), side: "left" },
    ];
    assert.equal(await verifyProof(makeProof(L2, path, ROOT4)), true);
  });

  it("leaf3 proof is valid", async () => {
    const path = [
      { sibling: toHex(L2),  side: "left" },
      { sibling: toHex(N01), side: "left" },
    ];
    assert.equal(await verifyProof(makeProof(L3, path, ROOT4)), true);
  });

  it("wrong sibling returns false", async () => {
    const path = [
      { sibling: toHex(L2),  side: "right" },  // wrong sibling
      { sibling: toHex(N23), side: "right" },
    ];
    assert.equal(await verifyProof(makeProof(L0, path, ROOT4)), false);
  });

  it("wrong root returns false", async () => {
    const path = [
      { sibling: toHex(L1),  side: "right" },
      { sibling: toHex(N23), side: "right" },
    ];
    const proof = makeProof(L0, path, ROOT4);
    proof.merkleRoot = "ff".repeat(32);
    assert.equal(await verifyProof(proof), false);
  });

  it("swapped side returns false", async () => {
    const path = [
      { sibling: toHex(L1),  side: "left" },   // wrong side
      { sibling: toHex(N23), side: "right" },
    ];
    assert.equal(await verifyProof(makeProof(L0, path, ROOT4)), false);
  });
});

describe("single-leaf tree", () => {
  it("empty proof path — root equals leaf", async () => {
    const leaf = sha256(Buffer.from("only leaf"));
    const proof = makeProof(leaf, [], leaf);
    assert.equal(await verifyProof(proof), true);
  });
});

describe("odd-leaf tree (3 leaves — duplicate)", () => {
  //   La  Lb  Lc  (Lc duplicated)
  //   Nab=H(La,Lb)  Ncc=H(Lc,Lc)
  //   ROOT=H(Nab,Ncc)
  it("leaf2 with duplicate sibling is valid", async () => {
    const La = sha256(Buffer.from("a"));
    const Lb = sha256(Buffer.from("b"));
    const Lc = sha256(Buffer.from("c"));
    const Nab  = combine(La, Lb);
    const Ncc  = combine(Lc, Lc);
    const root = combine(Nab, Ncc);
    const path = [
      { sibling: toHex(Lc),  side: "right" },  // duplicate sibling
      { sibling: toHex(Nab), side: "left"  },
    ];
    assert.equal(await verifyProof(makeProof(Lc, path, root)), true);
  });
});

describe("VerificationError cases", () => {
  it("malformed leaf hash raises VerificationError", async () => {
    const proof = makeProof(L0, [], ROOT4);
    proof.hash = "not-hex!!";
    await assert.rejects(
      () => verifyProof(proof),
      (err) => {
        assert.ok(err instanceof VerificationError);
        assert.ok(err.message.includes("Invalid leaf hash"));
        return true;
      }
    );
  });

  it("malformed sibling hex raises VerificationError", async () => {
    const proof = makeProof(L0, [{ sibling: "gg".repeat(32), side: "right" }], ROOT4);
    await assert.rejects(
      () => verifyProof(proof),
      (err) => {
        assert.ok(err instanceof VerificationError);
        assert.ok(err.message.includes("Invalid sibling hex"));
        return true;
      }
    );
  });

  it("unknown side raises VerificationError", async () => {
    const proof = makeProof(L0, [{ sibling: toHex(L1), side: "center" }], ROOT4);
    await assert.rejects(
      () => verifyProof(proof),
      (err) => {
        assert.ok(err instanceof VerificationError);
        assert.ok(err.message.includes("Unknown side"));
        return true;
      }
    );
  });

  it("malformed merkle_root raises VerificationError", async () => {
    const proof = makeProof(L0, [], ROOT4);
    proof.merkleRoot = "zzzz";
    await assert.rejects(
      () => verifyProof(proof),
      (err) => {
        assert.ok(err instanceof VerificationError);
        assert.ok(err.message.includes("Invalid merkle_root"));
        return true;
      }
    );
  });
});
