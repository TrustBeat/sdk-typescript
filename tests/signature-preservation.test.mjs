/** Signature Preservation: the SDK passes the extractor's submission through and maps the responses. */

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";

import { TrustBeat, NotFoundError, TrustBeatError } from "../dist/index.js";

const SUBMISSION = {
  submission_version: 1,
  extractor: { name: "trustbeat-signature", version: "1.0.0" },
  container: { format: "PAdES", name: "contract.pdf", size_bytes: 10,
               digests: { sha256: "a".repeat(64), sha512: "b".repeat(128), "sha3-512": "c".repeat(128) } },
  data_objects: [], signatures: [{ format: "CAdES", source: "pdf", signature_b64: "MA==", binding: [] }], timestamps: [],
};

const RECORD = {
  id: "01REC", status: "pending", created_at: "2026-10-13T10:00:00Z", client_ref: "contract-17",
  container: { format: "PAdES", name: "contract.pdf", sha256: "a".repeat(64) },
  signature_count: 1, peo: { sha256: "d".repeat(64), sha512: "e".repeat(128) },
  preservation: { profile: "https://trustbeat.eu/preservation/profile/pds-wst-v1", profile_status: "draft",
                  preserve_until: "2056-10-13T10:00:00Z" },
  evidence_record: { status: "pending" },
  signatures: [{ index: 0, format: "CAdES", indication: "TOTAL_PASSED" }],
};

const REPORT = {
  report_version: 1, record_id: "01REC", result: "failed", claim: "At least one step failed.",
  steps: [{ step: 1, name: "file", title: "The presented file is the preserved file", result: "failed",
            checked_by: ["extractor"], details: ["The digests differ."] }],
  signatures: [], evidence_record: [],
};

let originalFetch;
let calls;

/** Answers every call with `body` (JSON, or raw bytes with `contentType`); records the requests. */
function stub(status, body, contentType = "application/json") {
  originalFetch = globalThis.fetch;
  calls = [];
  const bytes = body instanceof Uint8Array ? body : new TextEncoder().encode(JSON.stringify(body));
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ url: String(url), method: init.method ?? "GET", headers: init.headers ?? {}, body: init.body });
    return {
      ok: status >= 200 && status < 300, status,
      headers: new Headers({ "Content-Type": contentType }),
      text: async () => new TextDecoder().decode(bytes),
      arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
    };
  };
}

function restore() {
  if (originalFetch !== undefined) { globalThis.fetch = originalFetch; originalFetch = undefined; }
}

const tb = () => new TrustBeat({ apiKey: "tb_live_test" });

describe("Signature Preservation", () => {
  afterEach(restore);

  it("preserveSignatures sends the submission unchanged, from text or an object", async () => {
    stub(202, RECORD);
    for (const given of [SUBMISSION, JSON.stringify(SUBMISSION)]) {
      const rec = await tb().preserveSignatures(given, { clientRef: "contract 17/a" });
      const c = calls.at(-1);
      assert.equal(c.method, "POST");
      assert.ok(c.url.endsWith("/v1/signature-preservation?client_ref=contract%2017%2Fa"));
      assert.deepEqual(JSON.parse(c.body), SUBMISSION);
      assert.equal(rec.id, "01REC");
      assert.equal(rec.status, "pending");
      assert.equal(rec.containerFormat, "PAdES");
      assert.equal(rec.peoSha256, "d".repeat(64));
      assert.equal(rec.clientRef, "contract-17");
      assert.equal(rec.preserveUntil, "2056-10-13T10:00:00Z");
      assert.equal(rec.evidenceRecordUrl, null);
      assert.equal(rec.signatures[0].indication, "TOTAL_PASSED");
    }
  });

  it("a submission must be a JSON object", async () => {
    await assert.rejects(() => tb().preserveSignatures("[1, 2]"), /JSON object/);
  });

  it("an invalid submission is a TrustBeatError with status 400", async () => {
    stub(400, { error: { code: "INVALID_SUBMISSION", message: "binding" } });
    await assert.rejects(() => tb().preserveSignatures(SUBMISSION), (e) => e instanceof TrustBeatError && e.status === 400);
  });

  it("get and list", async () => {
    stub(200, { ...RECORD, status: "preserved",
                evidence_record: { status: "ready", download_url: "https://api.trustbeat.eu/v1/public/proof/01REC/evidence-record.ers" } });
    const rec = await tb().getSignaturePreservation("01REC");
    assert.ok(calls[0].url.endsWith("/v1/signature-preservation/01REC"));
    assert.equal(rec.evidenceRecordStatus, "ready");
    assert.ok(rec.evidenceRecordUrl.endsWith("/evidence-record.ers"));
    restore();

    stub(200, { records: [{ ...RECORD, signatures: undefined }] });
    const recs = await tb().listSignaturePreservations({ limit: 10 });
    assert.ok(calls[0].url.endsWith("/v1/signature-preservation?limit=10"));
    assert.equal(recs.length, 1);
    assert.equal(recs[0].signatures, null);
  });

  it("unknown record: NotFoundError, also for the binary downloads", async () => {
    stub(404, { error: { code: "NOT_FOUND", message: "Record not found." } });
    await assert.rejects(() => tb().getSignaturePreservation("nope"), NotFoundError);
    await assert.rejects(() => tb().downloadSignaturePreservationPackage("nope"), NotFoundError);
    await assert.rejects(() => tb().verifySignaturePreservationPdf("nope", SUBMISSION), NotFoundError);
  });

  it("the package is the ZIP bytes", async () => {
    stub(200, new Uint8Array([0x50, 0x4b, 3, 4, 1]), "application/zip");
    const zip = await tb().downloadSignaturePreservationPackage("01REC");
    assert.ok(calls[0].url.endsWith("/v1/signature-preservation/01REC/package"));
    assert.deepEqual([...zip], [0x50, 0x4b, 3, 4, 1]);
  });

  it("verify returns the report", async () => {
    stub(200, REPORT);
    const rep = await tb().verifySignaturePreservation("01REC", JSON.stringify(SUBMISSION));
    assert.ok(calls[0].url.endsWith("/v1/signature-preservation/01REC/verify"));
    assert.deepEqual(JSON.parse(calls[0].body), SUBMISSION);
    assert.equal(rep.result, "failed");
    assert.equal(rep.steps[0].name, "file");
    assert.deepEqual(rep.steps[0].checkedBy, ["extractor"]);
    assert.equal(rep.raw.report_version, 1);
  });

  it("verify as PDF posts the submission and returns the PDF bytes", async () => {
    const pdf = new TextEncoder().encode("%PDF-1.7");
    stub(200, pdf, "application/pdf");
    const out = await tb().verifySignaturePreservationPdf("01REC", SUBMISSION);
    assert.ok(calls[0].url.endsWith("/v1/signature-preservation/01REC/verify?format=pdf"));
    assert.equal(calls[0].method, "POST");
    assert.equal(calls[0].headers["Content-Type"], "application/json");
    assert.deepEqual(JSON.parse(calls[0].body), SUBMISSION);
    assert.equal(new TextDecoder().decode(out), "%PDF-1.7");
  });
});
