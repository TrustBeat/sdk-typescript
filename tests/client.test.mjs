/**
 * Unit tests for the TrustBeat HTTP client.
 *
 * Uses node:test + node:assert (Node 18+ built-in, zero dependencies).
 * All network calls are intercepted by replacing globalThis.fetch with a stub.
 */

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { writeFile, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  TrustBeat,
  AuthError,
  NotFoundError,
  QuotaError,
  RateLimitError,
  TrustBeatError,
} from "../dist/index.js";

// ── Fetch stub helpers ────────────────────────────────────────────────────────

let originalFetch;

function stubFetch(status, body) {
  originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body),
  });
}

function restoreFetch() {
  if (originalFetch !== undefined) {
    globalThis.fetch = originalFetch;
    originalFetch = undefined;
  }
}

function captureFetch(status, body) {
  originalFetch = globalThis.fetch;
  let captured = null;
  globalThis.fetch = async (url, init) => {
    captured = { url, method: init?.method, headers: init?.headers, body: init?.body };
    return {
      ok: status >= 200 && status < 300,
      status,
      text: async () => JSON.stringify(body),
    };
  };
  return () => captured;
}

function anchorAcceptedPayload(id = "track-1") {
  return {
    id,
    hash: "a".repeat(64),
    hash_algorithm: "sha256",
    status: "pending",
    submitted_at: "2026-01-01T00:00:00Z",
    overage: false,
  };
}

function proofPayload(id = "track-1") {
  const leaf = "ab".repeat(32); // 64 hex chars
  const token = Buffer.from("DER_BYTES").toString("base64");
  return {
    id,
    hash: leaf,
    hash_algorithm: "sha256",
    batch_id: "batch-1",
    leaf_index: 0,
    merkle_root: leaf,
    proof_path: [],
    token,
    token_format: "rfc3161",
    tsa_serial: "42",
    provider: "sk-demo",
    anchored_at: "2026-01-01T00:10:00Z",
    client_ref: null,
    description: null,
  };
}

// ── anchor() ─────────────────────────────────────────────────────────────────

describe("anchor()", () => {
  afterEach(restoreFetch);

  it("returns an AnchorJob on success", async () => {
    stubFetch(202, anchorAcceptedPayload());
    const job = await new TrustBeat({ apiKey: "tb_live_test" }).anchor("a".repeat(64));
    assert.equal(job.id, "track-1");
    assert.equal(job.status, "pending");
    assert.equal(job.overage, false);
  });

  it("sends correct body and Authorization header", async () => {
    const getCaptured = captureFetch(202, anchorAcceptedPayload());
    await new TrustBeat({ apiKey: "tb_live_mykey" }).anchor("b".repeat(64), { clientRef: "ref-1" });
    const req = getCaptured();
    const body = JSON.parse(req.body);
    assert.equal(body.hash, "b".repeat(64));
    assert.equal(body.hash_algorithm, "SHA-256");
    assert.equal(body.client_ref, "ref-1");
    assert.equal(req.headers["Authorization"], "Bearer tb_live_mykey");
  });

  it("sends POST to /anchor", async () => {
    const getCaptured = captureFetch(202, anchorAcceptedPayload());
    await new TrustBeat({ apiKey: "tb_live_test" }).anchor("a".repeat(64));
    const req = getCaptured();
    assert.equal(req.method, "POST");
    assert.ok(req.url.endsWith("/anchor"));
  });
});

// ── anchorBatch() ─────────────────────────────────────────────────────────────

describe("anchorBatch()", () => {
  afterEach(restoreFetch);

  it("returns a BatchSubmission with items", async () => {
    stubFetch(202, {
      submission_id: "sub-1",
      accepted: [anchorAcceptedPayload("t1"), anchorAcceptedPayload("t2")],
      total: 2,
    });
    const sub = await new TrustBeat({ apiKey: "tb_live_test" }).anchorBatch(["a".repeat(64), "b".repeat(64)]);
    assert.equal(sub.submissionId, "sub-1");
    assert.equal(sub.items.length, 2);
    assert.equal(sub.items[0].id, "t1");
    assert.equal(sub.items[1].id, "t2");
  });

  it("empty array returns empty submission without a request", async () => {
    let fetchCalled = false;
    originalFetch = globalThis.fetch;
    globalThis.fetch = async () => { fetchCalled = true; return {}; };
    const result = await new TrustBeat({ apiKey: "tb_live_test" }).anchorBatch([]);
    assert.deepEqual(result, { submissionId: "", items: [] });
    assert.equal(fetchCalled, false);
    restoreFetch();
  });

  it("over 100 hashes throws Error", async () => {
    await assert.rejects(
      () => new TrustBeat({ apiKey: "tb_live_test" }).anchorBatch(Array(101).fill("a".repeat(64))),
      /maximum 100/
    );
  });
});

// ── getProof() ────────────────────────────────────────────────────────────────

describe("getProof()", () => {
  afterEach(restoreFetch);

  it("returns AnchorProof when anchored", async () => {
    stubFetch(200, proofPayload());
    const proof = await new TrustBeat({ apiKey: "tb_live_test" }).getProof("track-1");
    assert.ok(proof !== null);
    assert.deepEqual(proof.token, Buffer.from("DER_BYTES"));
    assert.equal(proof.tsaSerial, "42");
  });

  it("returns null when still pending (no merkle_root)", async () => {
    stubFetch(200, anchorAcceptedPayload());
    const result = await new TrustBeat({ apiKey: "tb_live_test" }).getProof("track-1");
    assert.equal(result, null);
  });
});

// ── anchorWait() ──────────────────────────────────────────────────────────────

describe("anchorWait()", () => {
  afterEach(restoreFetch);

  it("polls until proof is ready", async () => {
    let calls = 0;
    originalFetch = globalThis.fetch;
    globalThis.fetch = async () => {
      calls++;
      const body = calls === 1 ? anchorAcceptedPayload() : proofPayload();
      return { ok: true, status: 200, text: async () => JSON.stringify(body) };
    };

    const proof = await new TrustBeat({ apiKey: "tb_live_test" }).anchorWait("track-1", {
      pollIntervalSecs: 0.001,
    });
    assert.ok(proof !== null);
    assert.equal(calls, 2);
    restoreFetch();
  });

  it("throws TimeoutError after timeout", async () => {
    stubFetch(200, anchorAcceptedPayload());
    await assert.rejects(
      () =>
        new TrustBeat({ apiKey: "tb_live_test" }).anchorWait("track-1", {
          timeoutSecs: 0.001,
          pollIntervalSecs: 0.001,
        }),
      (err) => {
        assert.equal(err.name, "TimeoutError");
        return true;
      }
    );
  });
});

// ── verify() ─────────────────────────────────────────────────────────────────

describe("verify()", () => {
  it("returns true for a valid single-leaf proof", async () => {
    const leaf = createHash("sha256").update("content").digest("hex");
    const proof = {
      id: "x", hash: leaf, hashAlgorithm: "sha256",
      batchId: "b", leafIndex: 0, merkleRoot: leaf,
      proofPath: [], token: new Uint8Array(0),
      tokenFormat: "rfc3161", tsaSerial: "0",
      provider: "test", anchoredAt: "2026-01-01T00:00:00Z",
      clientRef: null, description: null,
    };
    assert.equal(await new TrustBeat({ apiKey: "tb_live_test" }).verify(proof), true);
  });

  it("returns false for an invalid proof", async () => {
    const leaf = createHash("sha256").update("content").digest("hex");
    const proof = {
      id: "x", hash: leaf, hashAlgorithm: "sha256",
      batchId: "b", leafIndex: 0, merkleRoot: "ff".repeat(32),
      proofPath: [], token: new Uint8Array(0),
      tokenFormat: "rfc3161", tsaSerial: "0",
      provider: "test", anchoredAt: "2026-01-01T00:00:00Z",
      clientRef: null, description: null,
    };
    assert.equal(await new TrustBeat({ apiKey: "tb_live_test" }).verify(proof), false);
  });
});

// ── Error handling ────────────────────────────────────────────────────────────

describe("error handling", () => {
  afterEach(restoreFetch);

  it("401 throws AuthError", async () => {
    stubFetch(401, { error: { message: "Bad key", code: "UNAUTHORIZED" } });
    await assert.rejects(
      () => new TrustBeat({ apiKey: "bad_key" }).anchor("a".repeat(64)),
      (err) => { assert.ok(err instanceof AuthError); return true; }
    );
  });

  it("402 throws QuotaError", async () => {
    stubFetch(402, { error: { message: "Quota exceeded" } });
    await assert.rejects(
      () => new TrustBeat({ apiKey: "tb_live_test" }).anchor("a".repeat(64)),
      (err) => { assert.ok(err instanceof QuotaError); return true; }
    );
  });

  it("404 throws NotFoundError", async () => {
    stubFetch(404, { error: { message: "Not found", code: "NOT_FOUND" } });
    await assert.rejects(
      () => new TrustBeat({ apiKey: "tb_live_test" }).getProof("nonexistent"),
      (err) => { assert.ok(err instanceof NotFoundError); return true; }
    );
  });

  it("429 throws RateLimitError", async () => {
    stubFetch(429, { error: { message: "Slow down" } });
    await assert.rejects(
      () => new TrustBeat({ apiKey: "tb_live_test" }).anchor("a".repeat(64)),
      (err) => { assert.ok(err instanceof RateLimitError); return true; }
    );
  });

  it("500 throws TrustBeatError with status 500", async () => {
    stubFetch(500, { error: { message: "Server error" } });
    await assert.rejects(
      () => new TrustBeat({ apiKey: "tb_live_test" }).anchor("a".repeat(64)),
      (err) => {
        assert.ok(err instanceof TrustBeatError);
        assert.equal(err.status, 500);
        return true;
      }
    );
  });

  it("empty apiKey throws Error", () => {
    assert.throws(() => new TrustBeat({ apiKey: "" }), /apiKey/);
  });
});

// ── anchorFile() ──────────────────────────────────────────────────────────────

describe("anchorFile", () => {
  afterEach(restoreFetch);

  async function withTempFile(content, fn) {
    const path = join(tmpdir(), `tb-test-${Date.now()}-${Math.random().toString(36).slice(2)}.bin`);
    await writeFile(path, content);
    try {
      return await fn(path);
    } finally {
      await unlink(path).catch(() => {});
    }
  }

  it("hashes file content and submits correct SHA-256", async () => {
    const content = Buffer.from("hello trustbeat");
    const expectedHash = createHash("sha256").update(content).digest("hex");
    let capturedBody;
    globalThis.fetch = async (_url, opts) => {
      capturedBody = JSON.parse(opts.body);
      return { ok: true, status: 202, text: async () => JSON.stringify(anchorAcceptedPayload("track-f1")) };
    };

    await withTempFile(content, async (path) => {
      const job = await new TrustBeat({ apiKey: "tb_live_test" }).anchorFile(path);
      assert.equal(job.id, "track-f1");
    });

    assert.equal(capturedBody.hash, expectedHash);
  });

  it("description defaults to the filename", async () => {
    let capturedBody;
    globalThis.fetch = async (_url, opts) => {
      capturedBody = JSON.parse(opts.body);
      return { ok: true, status: 202, text: async () => JSON.stringify(anchorAcceptedPayload()) };
    };

    await withTempFile(Buffer.from("data"), async (path) => {
      await new TrustBeat({ apiKey: "tb_live_test" }).anchorFile(path);
      assert.ok(capturedBody.description.endsWith(".bin"));
    });
  });

  it("custom description overrides filename", async () => {
    let capturedBody;
    globalThis.fetch = async (_url, opts) => {
      capturedBody = JSON.parse(opts.body);
      return { ok: true, status: 202, text: async () => JSON.stringify(anchorAcceptedPayload()) };
    };

    await withTempFile(Buffer.from("data"), async (path) => {
      await new TrustBeat({ apiKey: "tb_live_test" }).anchorFile(path, { description: "my-doc" });
    });

    assert.equal(capturedBody.description, "my-doc");
  });

  it("clientRef is forwarded", async () => {
    let capturedBody;
    globalThis.fetch = async (_url, opts) => {
      capturedBody = JSON.parse(opts.body);
      return { ok: true, status: 202, text: async () => JSON.stringify(anchorAcceptedPayload()) };
    };

    await withTempFile(Buffer.from("data"), async (path) => {
      await new TrustBeat({ apiKey: "tb_live_test" }).anchorFile(path, { clientRef: "ref-99" });
    });

    assert.equal(capturedBody.client_ref, "ref-99");
  });

  it("hashFile produces same digest as node:crypto", async () => {
    const content = Buffer.from("deterministic content 42");
    const expected = createHash("sha256").update(content).digest("hex");

    await withTempFile(content, async (path) => {
      const hash = await TrustBeat.hashFile(path);
      assert.equal(hash, expected);
    });
  });
});
