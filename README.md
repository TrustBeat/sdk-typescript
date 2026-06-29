# TrustBeat TypeScript / JavaScript SDK

Qualified electronic timestamps and Merkle anchoring — eIDAS-compliant, over a simple API.

## Install

```bash
npm install trustbeat
```

## Quickstart

```typescript
import { TrustBeat } from "trustbeat";

const tb = new TrustBeat({ apiKey: "tb_live_..." });

// Anchor a file (SHA-256 computed locally, file never leaves your machine)
const proof = await tb.anchorFile("contract.pdf");
console.log(proof.id);          // tracking ID
console.log(proof.anchoredAt);  // ISO 8601 timestamp
console.log(proof.merkleRoot);  // Merkle root of the batch

// Verify locally — no network call
const valid = tb.verify(proof);

// Anchor a raw SHA-256 hash
const job = await tb.anchor("e3b0c44298fc1c149afb4c8996fb92427ae41e4649b934ca495991b7852b855");
const waited = await tb.anchorWait(job.id);  // polls up to 11 min

```

## Requirements

- Node.js 18+ (uses native `fetch` and `crypto`)
- Zero runtime dependencies (stdlib only)

## Documentation

Full API reference and guides at [api.trustbeat.eu/docs](https://api.trustbeat.eu/docs)

## License

MIT — see [LICENSE](LICENSE)
