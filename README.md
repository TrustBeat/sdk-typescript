# TrustBeat TypeScript / JavaScript SDK

Qualified electronic timestamps and Merkle anchoring — eIDAS-compliant, over a simple API.

Part of **[TrustBeat](https://trustbeat.eu)** — digital trust infrastructure for the EU.
All SDKs (Python, TypeScript, Java, C#, Go): **[trustbeat.eu/sdks](https://trustbeat.eu/sdks)**.

## Install

```bash
npm install trustbeat
```

## Quickstart

```typescript
import { TrustBeat } from "trustbeat";

const tb = new TrustBeat({ apiKey: "tb_live_..." });

// Anchor a file (SHA-256 computed locally, file never leaves your machine).
// anchorFileWait() blocks until the proof is ready (next batch, up to 11 min).
const proof = await tb.anchorFileWait("contract.pdf");
console.log(proof.id);          // tracking ID
console.log(proof.anchoredAt);  // ISO 8601 timestamp
console.log(proof.merkleRoot);  // Merkle root of the batch

// Verify locally — no network call
const valid = tb.verify(proof);

// Or anchor a raw SHA-256 hash without blocking, then wait for the proof.
const job = await tb.anchor("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
const waited = await tb.anchorWait(job.id);  // polls up to 11 min

```

## Tamper-Evident Logs (NIS2)

Anchor a log hash together with canonical metadata for NIS2 Article 21 audit trails.
The server seals the metadata into the Merkle leaf, so the proof covers both the log
content and its context.

```typescript
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { TrustBeat } from "trustbeat";

const tb = new TrustBeat({ apiKey: "tb_live_..." });

// Hash the log yourself — content never leaves your machine.
const logHash = createHash("sha256").update(readFileSync("app.log")).digest("hex");

const job = await tb.anchorLog(logHash, {
  logSource: { uri: "/var/log/app.log", name: "Application log" },
  sourceIdentity: { hostname: "web-01", serviceName: "payments" },
  timeEnvelope: { startAt: "2026-04-15T00:00:00Z", endAt: "2026-04-15T23:59:59Z" },
}, { label: "incident-2026-05" });
console.log(job.id, job.combinedHash);

// Wait for the qualified anchor (next batch, up to 11 min).
const proof = await tb.anchorLogWait(job.id);
console.log(proof.verificationStatus); // "VERIFIED"
```

## Webhooks

If your account has a webhook secret configured, every delivery is signed with
an `X-TrustBeat-Signature` header. Verify it with the raw request body —
before any JSON parsing:

```ts
import { verifyWebhookSignature } from "trustbeat";

// body must be the raw bytes/string as received (e.g. express.raw())
if (!verifyWebhookSignature(rawBody, signatureHeader, webhookSecret)) {
  throw new Error("Invalid webhook signature");
}
```

Also available as `TrustBeat.verifyWebhookSignature(...)`. Rejects replays
older than 5 minutes by default (`toleranceSecs` option to override).

Portable proof bundles for offline verification: `exportAiDecision(id)`,
`exportVerification(id)`, `exportLog(id)` — each returns raw JSON bundle bytes.

## Requirements

- Node.js 18+ (uses native `fetch` and `crypto`)
- Zero runtime dependencies (stdlib only)

## Documentation

Full API reference and guides at [api.trustbeat.eu/docs](https://api.trustbeat.eu/docs)

## License

MIT — see [LICENSE](LICENSE)
