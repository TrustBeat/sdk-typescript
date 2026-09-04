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

import {
  verifyProof,
  verifyAuditEventProof,
  VerificationError,
} from "../dist/index.js";
import { parseAuditEventProof } from "../dist/models.js";

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

// ── merkle_algorithm dispatch (SDK 0.4.0) ─────────────────────────────────────

import {
  LEGACY_SHA256,
  RFC6962_SHA256,
  UnsupportedAlgorithmError,
} from "../dist/index.js";

function proofWith(hash, merkleRoot, proofPath = [], merkleAlgorithm = LEGACY_SHA256) {
  return {
    id: "p1",
    hash,
    hashAlgorithm: "SHA-256",
    batchId: "b1",
    leafIndex: 0,
    merkleRoot,
    proofPath,
    token: new Uint8Array(),
    tokenFormat: "RFC3161_DER",
    tsaSerial: "1",
    provider: "test",
    anchoredAt: "2026-01-01T00:00:00Z",
    clientRef: null,
    description: null,
    merkleAlgorithm,
    treeSize: null,
  };
}

describe("merkleAlgorithm dispatch", () => {
  it("treats a missing algorithm as legacy", async () => {
    // Proofs issued before the field existed must keep verifying forever.
    const leaf = sha256(Buffer.from("a")).toString("hex");
    const p = proofWith(leaf, leaf);
    delete p.merkleAlgorithm;
    assert.equal(await verifyProof(p), true);
  });

  it("rfc6962 hashes the leaf, so a one-leaf root is not the leaf", async () => {
    const leaf = sha256(Buffer.from("a"));
    const rfcRoot = sha256(Buffer.concat([Buffer.from([0x00]), leaf])).toString("hex");
    assert.equal(
      await verifyProof(proofWith(leaf.toString("hex"), rfcRoot, [], RFC6962_SHA256)),
      true
    );
    assert.equal(
      await verifyProof(
        proofWith(leaf.toString("hex"), leaf.toString("hex"), [], RFC6962_SHA256)
      ),
      false
    );
  });

  it("reproduces the RFC 6962 reference vector for [a,b,c]", async () => {
    const a = sha256(Buffer.from("a")).toString("hex");
    const path = [
      { sibling: "a0d9f0a50b35b9f7d7edc57fb64f4771ddef0fefeaca4e6f949a1514db5b136d", side: "right" },
      { sibling: "6a3fc11b79f836bda340e75c8906e961b8adf4d6a08a2b992e3f38cd6ff38ebf", side: "right" },
    ];
    const root = "cac3d448d4e20a2ad5eae1f500e63c2a7f9217cd14572ba7fd22e26dc1ec2648";
    assert.equal(await verifyProof(proofWith(a, root, path, RFC6962_SHA256)), true);
  });

  // Vectors below are taken verbatim from Google's transparency-dev/merkle
  // (rfc6962_test.go) — a third-party implementation.
  it("leaf hash matches the upstream RFC 6962 vector", async () => {
    // SHA-256(0x00 || "L123456")
    assert.equal(
      await verifyProof(proofWith("4c313233343536", "395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56", [], RFC6962_SHA256)),
      true
    );
  });

  it("rfc6962 left sibling applies the node prefix", async () => {
    // Two-leaf tree whose BOTH leaf hashes are upstream vectors.
    // Exercises side="left", which no other rfc6962 test reaches.
    assert.equal(
      await verifyProof(
        proofWith("4c313233343536", "bf9ae70442844df993ca0001a7c8a095c5f145857960b1ee389df6cbe84b5bf3", [{ sibling: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", side: "left" }], RFC6962_SHA256)
      ),
      true
    );
  });

  it("throws on an unknown algorithm instead of returning false", async () => {
    // "I cannot check this" must not look like "this proof is forged".
    const leaf = sha256(Buffer.from("a")).toString("hex");
    await assert.rejects(
      () => verifyProof(proofWith(leaf, leaf, [], "sha3-512-tree")),
      UnsupportedAlgorithmError
    );
  });
});

// ── Shared RFC 6962 fixture ───────────────────────────────────────────────────

import { readFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

function loadFixture() {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 8; i++) {
    const f = join(dir, "tests", "fixtures", "rfc6962-proofs.json");
    if (existsSync(f)) return JSON.parse(readFileSync(f, "utf8"));
    dir = resolve(dir, "..");
  }
  throw new Error("rfc6962-proofs.json not found");
}

describe("shared RFC 6962 fixture", () => {
  it("every fixture proof verifies", async () => {
    const doc = loadFixture();
    for (const p of doc.proofs) {
      const proof = proofWith(p.hash, p.merkle_root, p.proof_path, p.merkle_algorithm);
      assert.equal(await verifyProof(proof), true, `leaf ${p.leaf_index} failed`);
    }
  });

  it("a tampered fixture proof fails", async () => {
    // Guards against the suite passing because verification is a no-op.
    const doc = loadFixture();
    const p = doc.proofs[0];
    const proof = proofWith("00".repeat(32), p.merkle_root, p.proof_path, p.merkle_algorithm);
    assert.equal(await verifyProof(proof), false);
  });
});

// ── Audit event proof verification ────────────────────────────────────────────
// Including the compatibility rule that matters most: a proof from a server
// older than API 1.46 has no merkleRoot and must be reported as "cannot check",
// never as "invalid".

describe("verifyAuditEventProof", () => {
  const sha = (b) => createHash("sha256").update(b).digest();

  function rfc6962Proof(over = {}) {
    const a = sha(Buffer.from("audit-a"));
    const b = sha(Buffer.from("audit-b"));
    const la = sha(Buffer.concat([Buffer.from([0x00]), a]));
    const lb = sha(Buffer.concat([Buffer.from([0x00]), b]));
    const root = sha(Buffer.concat([Buffer.from([0x01]), la, lb]));
    return parseAuditEventProof({
      event_id: "evt_1",
      canonical_hash: a.toString("hex"),
      batch_id: "batch_1",
      leaf_index: 0,
      merkle_path: [{ sibling: lb.toString("hex"), side: "right" }],
      anchored_at: "2026-01-01T00:00:00Z",
      merkle_root: root.toString("hex"),
      tree_size: 2,
      merkle_algorithm: "rfc6962-sha256",
      ...over,
    });
  }

  // Exactly what api.trustbeat.eu returns today: no merkle_root, no tree_size,
  // no merkle_algorithm.
  const OLD_SERVER = {
    event_id: "evt_old",
    canonical_hash: "ab".repeat(32),
    batch_id: "batch_old",
    leaf_index: 0,
    merkle_path: [{ sibling: "cd".repeat(32), side: "right" }],
    anchored_at: "2026-01-01T00:00:00Z",
  };

  it("verifies a valid RFC 6962 audit proof", async () => {
    assert.equal(await verifyAuditEventProof(rfc6962Proof()), true);
  });

  it("returns false for a tampered root", async () => {
    assert.equal(
      await verifyAuditEventProof(rfc6962Proof({ merkle_root: "aa".repeat(32) })),
      false
    );
  });

  it("verifies a legacy audit proof under the legacy fold", async () => {
    const a = sha(Buffer.from("audit-a"));
    const b = sha(Buffer.from("audit-b"));
    const root = sha(Buffer.concat([a, b]));
    const p = rfc6962Proof({
      canonical_hash: a.toString("hex"),
      merkle_path: [{ sibling: b.toString("hex"), side: "right" }],
      merkle_root: root.toString("hex"),
      merkle_algorithm: "trustbeat-legacy-sha256",
    });
    assert.equal(await verifyAuditEventProof(p), true);
  });

  it("parses an old-server proof and defaults the algorithm to legacy", () => {
    const p = parseAuditEventProof(OLD_SERVER);
    assert.equal(p.eventId, "evt_old");
    assert.equal(p.merkleRoot, undefined);
    assert.equal(p.treeSize, undefined);
    assert.equal(p.merkleAlgorithm, "trustbeat-legacy-sha256");
    assert.equal(p.merklePath.length, 1);
  });

  it("throws IncompleteProofError rather than reporting an old-server proof invalid", async () => {
    const p = parseAuditEventProof(OLD_SERVER);
    await assert.rejects(() => verifyAuditEventProof(p), (e) => {
      assert.equal(e.name, "IncompleteProofError");
      assert.ok(!(e instanceof VerificationError));
      assert.match(e.message, /merkleRoot/);
      return true;
    });
  });

  it("throws UnsupportedAlgorithmError for an unknown algorithm", async () => {
    const p = rfc6962Proof({ merkle_algorithm: "sha3-future" });
    await assert.rejects(() => verifyAuditEventProof(p), (e) => {
      assert.equal(e.name, "UnsupportedAlgorithmError");
      return true;
    });
  });
});
