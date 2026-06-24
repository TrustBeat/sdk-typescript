/**
 * Convenience hashing helpers.
 *
 * All functions return a lowercase hex string suitable for passing to anchor().
 * Uses node:crypto (Node 18+). For browser use, bundle with a polyfill.
 */

import { createHash } from "node:crypto";

/**
 * SHA-256 hash of an arbitrary Buffer, ArrayBuffer, or Uint8Array.
 * Use this when you already have binary data in memory.
 */
export async function hashBuffer(data: Buffer | ArrayBuffer | Uint8Array): Promise<string> {
  // `update()` accepts an ArrayBufferView (Buffer/Uint8Array) but not a bare
  // ArrayBuffer — wrap that case in a Uint8Array view.
  const view = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
  return createHash("sha256").update(view).digest("hex");
}

/**
 * SHA-256 hash of a UTF-8 string.
 * Useful for hashing canonical JSON, IDs, or any text content.
 */
export async function hashString(text: string): Promise<string> {
  return createHash("sha256").update(text, "utf8").digest("hex");
}
