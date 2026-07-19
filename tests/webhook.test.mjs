/**
 * Unit tests for webhook signature verification — fully offline.
 *
 * Signatures are constructed exactly the way the server builds them
 * (WebhookDispatcher.scala): hex(HMAC-SHA256(utf8(secret), "<ts>.<body>")).
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";

import { TrustBeat, verifyWebhookSignature, VerificationError } from "../dist/index.js";

const SECRET = "ab".repeat(32); // hex-looking string; key is its UTF-8 bytes
const BODY = Buffer.from('{"event":"anchor.completed","id":"track-1","hash":"aa"}');
const NOW = 1752000000;

function sign(body, secret, ts) {
  const mac = createHmac("sha256", Buffer.from(secret, "utf-8"))
    .update(Buffer.concat([Buffer.from(`${ts}.`), body]))
    .digest("hex");
  return `t=${ts},v1=${mac}`;
}

describe("verifyWebhookSignature()", () => {
  it("accepts a valid signature", () => {
    const header = sign(BODY, SECRET, NOW);
    assert.equal(verifyWebhookSignature(BODY, header, SECRET, { now: NOW }), true);
  });

  it("treats string payload the same as bytes", () => {
    const header = sign(BODY, SECRET, NOW);
    assert.equal(
      verifyWebhookSignature(BODY.toString("utf-8"), header, SECRET, { now: NOW }),
      true,
    );
  });

  it("keys the HMAC with utf8(secret), not decoded hex", () => {
    const mac = createHmac("sha256", Buffer.from(SECRET, "hex"))
      .update(Buffer.concat([Buffer.from(`${NOW}.`), BODY]))
      .digest("hex");
    assert.equal(
      verifyWebhookSignature(BODY, `t=${NOW},v1=${mac}`, SECRET, { now: NOW }),
      false,
    );
  });

  it("rejects a tampered payload", () => {
    const header = sign(BODY, SECRET, NOW);
    const tampered = Buffer.from(BODY.toString().replace("track-1", "track-2"));
    assert.equal(verifyWebhookSignature(tampered, header, SECRET, { now: NOW }), false);
  });

  it("rejects the wrong secret", () => {
    const header = sign(BODY, SECRET, NOW);
    assert.equal(
      verifyWebhookSignature(BODY, header, "cd".repeat(32), { now: NOW }),
      false,
    );
  });

  it("accepts an uppercase hex signature", () => {
    const mac = createHmac("sha256", Buffer.from(SECRET, "utf-8"))
      .update(Buffer.concat([Buffer.from(`${NOW}.`), BODY]))
      .digest("hex")
      .toUpperCase();
    assert.equal(
      verifyWebhookSignature(BODY, `t=${NOW},v1=${mac}`, SECRET, { now: NOW }),
      true,
    );
  });

  // ── Replay window ──────────────────────────────────────────────────────────

  it("rejects a stale timestamp", () => {
    const header = sign(BODY, SECRET, NOW - 301);
    assert.equal(verifyWebhookSignature(BODY, header, SECRET, { now: NOW }), false);
  });

  it("rejects a future timestamp", () => {
    const header = sign(BODY, SECRET, NOW + 301);
    assert.equal(verifyWebhookSignature(BODY, header, SECRET, { now: NOW }), false);
  });

  it("accepts a timestamp exactly at the tolerance boundary", () => {
    const header = sign(BODY, SECRET, NOW - 300);
    assert.equal(verifyWebhookSignature(BODY, header, SECRET, { now: NOW }), true);
  });

  it("honours a custom tolerance", () => {
    const header = sign(BODY, SECRET, NOW - 500);
    assert.equal(verifyWebhookSignature(BODY, header, SECRET, { now: NOW }), false);
    assert.equal(
      verifyWebhookSignature(BODY, header, SECRET, { now: NOW, toleranceSecs: 600 }),
      true,
    );
  });

  // ── Malformed input ────────────────────────────────────────────────────────

  it("throws on malformed headers", () => {
    for (const bad of ["", "v1=abc", "t=123", "t=abc,v1=def", "nonsense"]) {
      assert.throws(
        () => verifyWebhookSignature(BODY, bad, SECRET, { now: NOW }),
        VerificationError,
        `header: ${JSON.stringify(bad)}`,
      );
    }
  });

  it("throws on an empty secret", () => {
    const header = sign(BODY, SECRET, NOW);
    assert.throws(
      () => verifyWebhookSignature(BODY, header, "", { now: NOW }),
      VerificationError,
    );
  });

  it("tolerates extra header parts (future scheme versions)", () => {
    const header = `${sign(BODY, SECRET, NOW)},v2=futurestuff`;
    assert.equal(verifyWebhookSignature(BODY, header, SECRET, { now: NOW }), true);
  });

  // ── Client static method ───────────────────────────────────────────────────

  it("is exposed as a static method on TrustBeat", () => {
    const header = sign(BODY, SECRET, NOW);
    assert.equal(
      TrustBeat.verifyWebhookSignature(BODY, header, SECRET, { now: NOW }),
      true,
    );
  });
});
