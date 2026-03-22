/**
 * TrustBeat HTTP client.
 *
 * Zero runtime dependencies — uses globalThis.fetch (Node 18+ / browser).
 */

import {
  TrustBeatError,
  AuthError,
  NotFoundError,
  QuotaError,
  RateLimitError,
} from "./exceptions.js";
import {
  AnchorJob,
  AnchorProof,
  TimestampResult,
  parseAnchorJob,
  parseProof,
  parseTimestamp,
  looksLikeProof,
} from "./models.js";
import { verifyProof } from "./verify.js";

// ── Options types ─────────────────────────────────────────────────────────────

export interface TrustBeatOptions {
  /** Your TrustBeat API key (tb_live_... or tb_test_...). */
  apiKey: string;
  /**
   * Base URL of the TrustBeat API.
   * Defaults to "https://api.trustbeat.eu/v1".
   */
  baseUrl?: string;
  /** Request timeout in milliseconds. Defaults to 30 000. */
  timeoutMs?: number;
}

export interface AnchorOptions {
  /** Your own reference ID, stored and echoed back in proof responses. */
  clientRef?: string;
  /** Human-readable description of the content being anchored. */
  description?: string;
}

export interface AnchorWaitOptions {
  /** Maximum seconds to wait for proof. Defaults to 660 (11 min). */
  timeoutSecs?: number;
  /** Polling interval in seconds. Defaults to 15. */
  pollIntervalSecs?: number;
}

// ── Client ────────────────────────────────────────────────────────────────────

export class TrustBeat {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(options: TrustBeatOptions) {
    if (!options.apiKey) throw new Error("apiKey must not be empty");
    this.apiKey = options.apiKey;
    this.baseUrl = (options.baseUrl ?? "https://api.trustbeat.eu/v1").replace(/\/$/, "");
    this.timeoutMs = options.timeoutMs ?? 30_000;
  }

  // ── Low-level HTTP ─────────────────────────────────────────────────────────

  private async request<T>(
    method: string,
    path: string,
    body?: unknown
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.apiKey}`,
      Accept: "application/json",
    };
    if (body !== undefined) headers["Content-Type"] = "application/json";

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let response: Response;
    try {
      response = await fetch(url, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    let data: unknown;
    const text = await response.text();
    try {
      data = JSON.parse(text);
    } catch {
      data = { error: { message: text } };
    }

    if (!response.ok) {
      const msg =
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (data as any)?.error?.message ?? `HTTP ${response.status}`;
      switch (response.status) {
        case 401: throw new AuthError(msg);
        case 402: throw new QuotaError(msg);
        case 404: throw new NotFoundError(msg);
        case 429: throw new RateLimitError(msg);
        default:  throw new TrustBeatError(msg, response.status);
      }
    }

    return data as T;
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Submit a single SHA-256 hash for anchoring.
   * Returns an AnchorJob; use getProof() or anchorWait() to retrieve the proof.
   */
  async anchor(hash: string, options: AnchorOptions = {}): Promise<AnchorJob> {
    const body: Record<string, unknown> = {
      hash,
      hash_algorithm: "sha256",
    };
    if (options.clientRef) body.client_ref = options.clientRef;
    if (options.description) body.description = options.description;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = await this.request<any>("POST", "/anchors", body);
    return parseAnchorJob(data);
  }

  /**
   * Submit up to 100 SHA-256 hashes in a single batch request.
   * Returns an empty array immediately for an empty input.
   */
  async anchorBatch(hashes: string[], options: AnchorOptions = {}): Promise<AnchorJob[]> {
    if (hashes.length === 0) return [];
    if (hashes.length > 100) {
      throw new Error("anchorBatch: maximum 100 hashes per request");
    }
    const body: Record<string, unknown> = {
      hashes: hashes.map((h) => ({ hash: h, hash_algorithm: "sha256" })),
    };
    if (options.clientRef) body.client_ref = options.clientRef;
    if (options.description) body.description = options.description;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = await this.request<any>("POST", "/anchors/batch", body);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (data.accepted as any[]).map(parseAnchorJob);
  }

  /**
   * Retrieve a proof by tracking ID.
   * Returns null if the anchor is still pending (not yet included in a batch).
   */
  async getProof(trackingId: string): Promise<AnchorProof | null> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = await this.request<any>("GET", `/anchors/${encodeURIComponent(trackingId)}`);
    if (!looksLikeProof(data)) return null;
    return parseProof(data);
  }

  /**
   * Poll until the proof is ready, then return it.
   * Throws TimeoutError if the proof is not ready within timeoutSecs.
   */
  async anchorWait(
    trackingId: string,
    options: AnchorWaitOptions = {}
  ): Promise<AnchorProof> {
    const timeoutSecs = options.timeoutSecs ?? 660;
    const pollIntervalSecs = options.pollIntervalSecs ?? 15;
    const deadline = Date.now() + timeoutSecs * 1000;

    while (true) {
      const proof = await this.getProof(trackingId);
      if (proof !== null) return proof;
      if (Date.now() >= deadline) {
        throw Object.assign(new Error(`anchorWait timed out after ${timeoutSecs}s`), {
          name: "TimeoutError",
        });
      }
      await new Promise((resolve) =>
        setTimeout(resolve, pollIntervalSecs * 1000)
      );
    }
  }

  /**
   * Verify a proof locally — no network call.
   * Returns true if the Merkle path and root are consistent, false otherwise.
   */
  async verify(proof: AnchorProof): Promise<boolean> {
    return verifyProof(proof);
  }

  /**
   * Request a direct (non-Merkle) qualified timestamp for a single hash.
   * Returns the full TimestampResult including the RFC 3161 token bytes.
   */
  async timestamp(hash: string, options: AnchorOptions = {}): Promise<TimestampResult> {
    const body: Record<string, unknown> = {
      hash,
      hash_algorithm: "sha256",
    };
    if (options.clientRef) body.client_ref = options.clientRef;
    if (options.description) body.description = options.description;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = await this.request<any>("POST", "/timestamps", body);
    return parseTimestamp(data);
  }
}
