/**
 * Webhook signature verification — no network call.
 *
 * TrustBeat signs every webhook delivery for accounts with a webhook secret
 * configured. Each request carries the header:
 *
 *   X-TrustBeat-Signature: t=<unix_ts>,v1=<hex(HMAC-SHA256(secret, "<ts>.<body>"))>
 *
 * The HMAC key is the UTF-8 bytes of the secret string exactly as shown in
 * the dashboard (it is *not* hex-decoded first). The signed payload is the
 * ASCII timestamp, a literal ".", and the raw request body bytes.
 *
 * A constant-time comparison is used for the signature check. The timestamp
 * bounds the window for replaying a captured delivery (default 5 minutes).
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import { VerificationError } from "./exceptions.js";

export interface WebhookVerifyOptions {
  /** Max allowed |now - t| in seconds (default 300). */
  toleranceSecs?: number;
  /** Override the current unix time (for testing). */
  now?: number;
}

/**
 * Verify the `X-TrustBeat-Signature` header of a webhook delivery.
 *
 * Pass the **raw request body** exactly as received — do not re-serialize the
 * JSON, as any formatting difference changes the signature.
 *
 * Returns `true` if the signature is valid and the timestamp is within
 * tolerance. Returns `false` on signature mismatch or a timestamp outside the
 * tolerance window (possible replay). Throws {@link VerificationError} if the
 * header or secret is malformed.
 *
 * @param payload - Raw request body (bytes as received, or string).
 * @param signatureHeader - Value of the `X-TrustBeat-Signature` header.
 * @param secret - Webhook secret from your TrustBeat dashboard.
 */
export function verifyWebhookSignature(
  payload: Uint8Array | string,
  signatureHeader: string,
  secret: string,
  options: WebhookVerifyOptions = {},
): boolean {
  if (!secret) throw new VerificationError("Webhook secret must not be empty");
  if (!signatureHeader) {
    throw new VerificationError("Signature header must not be empty");
  }

  let ts: string | undefined;
  let sigHex: string | undefined;
  for (const part of signatureHeader.split(",")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1);
    if (key === "t") ts = value;
    else if (key === "v1") sigHex = value;
  }
  if (!ts || !sigHex) {
    throw new VerificationError(
      `Malformed signature header (expected 't=<ts>,v1=<hex>'): ${signatureHeader}`,
    );
  }
  if (!/^\d+$/.test(ts)) {
    throw new VerificationError(`Malformed signature timestamp: ${ts}`);
  }

  const toleranceSecs = options.toleranceSecs ?? 300;
  const now = options.now ?? Math.floor(Date.now() / 1000);
  if (Math.abs(now - Number(ts)) > toleranceSecs) return false;

  const body =
    typeof payload === "string" ? Buffer.from(payload, "utf-8") : Buffer.from(payload);
  const signed = Buffer.concat([Buffer.from(`${ts}.`, "ascii"), body]);
  const expected = createHmac("sha256", Buffer.from(secret, "utf-8"))
    .update(signed)
    .digest("hex");

  const a = Buffer.from(expected, "utf-8");
  const b = Buffer.from(sigHex.toLowerCase(), "utf-8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
