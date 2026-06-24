#!/usr/bin/env node
/**
 * TrustBeat TypeScript SDK smoke CLI — drives the SDK against a LIVE API.
 *
 * Driven by tests/e2e/sdk_smoke.py (the orchestrator). Requires a built dist
 * (`npm install --no-save typescript && npx tsc`). Commands:
 *
 *   submit              anchor TB_HASH, print the tracking id
 *   verify <id>         fetch the proof via the SDK, check the contract, verify locally
 *   submit-batch        anchor a batch derived from TB_BATCH_SEED/TB_BATCH_N, print submission id
 *   verify-batch <id>   fetch batch proofs, check the contract, verify each locally
 *
 * Env: TB_BASE_URL (includes /v1), TB_API_KEY, TB_HASH, TB_BATCH_SEED, TB_BATCH_N
 * Exit 0 on success, non-zero on any failure.
 */

import { createHash } from "node:crypto";
import { TrustBeat } from "./dist/index.js";

function client() {
  return new TrustBeat({ apiKey: process.env.TB_API_KEY, baseUrl: process.env.TB_BASE_URL });
}

function fail(msg) {
  console.error(msg);
  process.exit(1);
}

function batchHashes() {
  const seed = process.env.TB_BATCH_SEED;
  const n = parseInt(process.env.TB_BATCH_N, 10);
  const out = [];
  for (let i = 0; i < n; i++) {
    out.push(createHash("sha256").update(`${seed}::${i}`).digest("hex"));
  }
  return out;
}

try {
  const cmd = process.argv[2];

  if (cmd === "submit") {
    const job = await client().anchor(process.env.TB_HASH);
    if (!job.id) fail("submit: empty tracking id");
    console.log(job.id);

  } else if (cmd === "verify") {
    const id = process.argv[3];
    if (!id) fail("usage: smoke.mjs verify <id>");
    const expected = process.env.TB_HASH;
    const c = client();
    const proof = await c.getProof(id);
    if (!proof) fail(`verify: proof for ${id} not ready`);
    if (expected && proof.hash.toLowerCase() !== expected.toLowerCase()) {
      fail(`verify: hash echo mismatch ${proof.hash} != ${expected}`);
    }
    if (!proof.merkleRoot) fail("verify: empty merkleRoot");
    if (!proof.token || proof.token.length === 0) fail("verify: empty token");
    if ((await c.verify(proof)) !== true) fail("verify: local Merkle verification failed");
    console.log(`OK id=${id} root=${proof.merkleRoot.slice(0, 16)}… token=${proof.token.length}B`);

  } else if (cmd === "submit-batch") {
    const hashes = batchHashes();
    const sub = await client().anchorBatch(hashes);
    if (!sub.submissionId) fail("submit-batch: empty submission_id");
    if (sub.items.length !== hashes.length) fail(`submit-batch: accepted ${sub.items.length} != ${hashes.length}`);
    console.log(sub.submissionId);

  } else if (cmd === "verify-batch") {
    const sid = process.argv[3];
    if (!sid) fail("usage: smoke.mjs verify-batch <id>");
    const expected = new Set(batchHashes().map((h) => h.toLowerCase()));
    const c = client();
    const proofs = await c.getBatchProofs(sid);
    if (proofs.length !== expected.size) fail(`verify-batch: got ${proofs.length} proofs, want ${expected.size}`);
    for (const p of proofs) {
      if (!expected.has(p.hash.toLowerCase())) fail(`verify-batch: unexpected proof hash ${p.hash}`);
      if (!p.merkleRoot || !p.token || p.token.length === 0) fail(`verify-batch: empty merkleRoot/token for ${p.id}`);
      if ((await c.verify(p)) !== true) fail(`verify-batch: local Merkle verification failed for ${p.id}`);
    }
    console.log(`OK batch sid=${sid} n=${proofs.length}`);

  } else {
    fail(`unknown command: ${cmd}`);
  }
} catch (e) {
  fail(String((e && e.message) || e));
}
