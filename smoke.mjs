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
import { readFileSync } from "node:fs";
import { TrustBeat } from "./dist/index.js";

// Fixed AI-decision metadata — only the input/output hashes vary per run.
const AI_META = {
  modelId: "claude-opus-4-8",
  systemName: "trustbeat-sdk-smoke",
  riskCategory: "employment",
  decisionType: "classification",
  humanOversight: true,
  timeEnvelope: { startedAt: "2026-06-29T10:00:00Z", completedAt: "2026-06-29T10:00:01Z" },
};

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

  } else if (cmd === "submit-ai") {
    const job = await client().anchorAiDecision(process.env.TB_AI_INPUT, process.env.TB_AI_OUTPUT, AI_META);
    if (!job.id) fail("submit-ai: empty tracking id");
    console.log(job.id);

  } else if (cmd === "verify-ai") {
    const id = process.argv[3];
    if (!id) fail("usage: smoke.mjs verify-ai <id>");
    const inHash = process.env.TB_AI_INPUT, outHash = process.env.TB_AI_OUTPUT;
    const c = client();
    const proof = await c.getAiDecisionProof(id);
    if (!proof) fail(`verify-ai: proof for ${id} not ready`);
    if (proof.inputHash.toLowerCase() !== inHash.toLowerCase())
      fail(`verify-ai: input_hash echo mismatch ${proof.inputHash} != ${inHash}`);
    if (proof.outputHash.toLowerCase() !== outHash.toLowerCase())
      fail(`verify-ai: output_hash echo mismatch ${proof.outputHash} != ${outHash}`);
    if (proof.verificationStatus !== "VERIFIED") fail(`verify-ai: status ${proof.verificationStatus} != VERIFIED`);
    if (!proof.proof) fail("verify-ai: missing Merkle proof");
    if ((await c.verify(proof.proof)) !== true) fail("verify-ai: local Merkle verification failed");
    console.log(`OK ai id=${id} combined=${proof.combinedHash.slice(0, 16)}…`);

  } else if (cmd === "submit-file") {
    const job = await client().anchorFile(process.env.TB_FILE_PATH);
    if (!job.id) fail("submit-file: empty tracking id");
    console.log(job.id);

  } else if (cmd === "submit-audit") {
    const eventId = await client().submitAuditEvent({
      trailCategory: process.env.TB_AUDIT_CATEGORY,
      actor: process.env.TB_AUDIT_ACTOR,
      action: process.env.TB_AUDIT_ACTION,
      ts: process.env.TB_AUDIT_TS,
    });
    if (!eventId) fail("submit-audit: empty event_id");
    console.log(eventId);

  } else if (cmd === "verify-audit") {
    const id = process.argv[3];
    if (!id) fail("usage: smoke.mjs verify-audit <id>");
    const c = client();
    const proof = await c.getAuditEventProof(id);
    if (!proof) fail(`verify-audit: proof for ${id} not ready`);
    if (proof.eventId !== id) fail(`verify-audit: event_id echo mismatch ${proof.eventId} != ${id}`);
    if (!proof.canonicalHash) fail("verify-audit: empty canonical_hash");
    if (!proof.batchId) fail("verify-audit: empty batch_id");
    if (proof.leafIndex < 0 || !Array.isArray(proof.merklePath)) fail("verify-audit: invalid leaf_index/merkle_path");
    const events = await c.listAuditEvents({ trailCategory: process.env.TB_AUDIT_CATEGORY });
    if (!events.some((e) => e.eventId === id)) fail(`verify-audit: ${id} not returned by listAuditEvents`);
    console.log(`OK audit id=${id} batch=${proof.batchId.slice(0, 12)}… leaf=${proof.leafIndex}`);

  } else if (cmd === "verify-sig") {
    const doc = readFileSync(process.env.TB_SIG_DOC);
    const expected = process.env.TB_SIG_DOCHASH;
    const report = await client().verifySignature(doc, process.env.TB_SIG_FORMAT);
    if (report.documentHash.toLowerCase() !== expected.toLowerCase())
      fail(`verify-sig: document_hash mismatch ${report.documentHash} != ${expected}`);
    if (!report.verdict) fail("verify-sig: empty verdict");
    if (!report.signatures || report.signatures.length === 0) fail("verify-sig: report has no signatures");
    console.log(`OK sig verdict=${report.verdict} signatures=${report.signatures.length}`);

  } else if (cmd === "validate-cert") {
    const cert = readFileSync(process.env.TB_CERT_PATH);
    const res = await client().validateCertificate(cert);
    if (!res.subject) fail("validate-cert: empty subject");
    if (!res.issuer) fail("validate-cert: empty issuer");
    if (!res.validatedAt) fail("validate-cert: empty validated_at");
    console.log(`OK cert subject=${res.subject.slice(0, 24)}… qualified=${res.qualified}`);

  } else {
    fail(`unknown command: ${cmd}`);
  }
} catch (e) {
  fail(String((e && e.message) || e));
}
