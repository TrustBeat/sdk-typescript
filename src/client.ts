/**
 * TrustBeat HTTP client.
 *
 * Zero runtime dependencies — uses globalThis.fetch (Node 18+ / browser).
 */

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { basename } from "node:path";
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
  BatchSubmission,
  BatchStatus,
  AiDecisionMetadata,
  AiDecisionJob,
  AiDecisionProof,
  VerificationReport,
  VerificationJob,
  CertificateValidationResult,
  AuditEvent,
  AuditEventProof,
  AuditExportJob,
  LogMetadata,
  LogAnchorJob,
  LogStatus,
  LogAnchorListItem,
  LogProof,
  parseAnchorJob,
  parseProof,
  parseBatchSubmission,
  parseBatchStatus,
  parseAiDecisionJob,
  parseAiDecisionProof,
  parseVerificationReport,
  parseVerificationJob,
  parseCertValidationResult,
  parseAuditEvent,
  parseAuditEventProof,
  parseAuditExportJob,
  parseLogAnchorJob,
  parseLogStatus,
  parseLogAnchorListItem,
  parseLogProof,
  logMetadataToJson,
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
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        case 404: throw new NotFoundError(msg, (data as any)?.error?.code ?? "NOT_FOUND");
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
      hash_algorithm: "SHA-256",
    };
    if (options.clientRef) body.client_ref = options.clientRef;
    if (options.description) body.description = options.description;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = await this.request<any>("POST", "/anchor", body);
    return parseAnchorJob(data);
  }

  /**
   * Submit up to 100 SHA-256 hashes in a single batch request.
   * Returns a BatchSubmission with a submission_id grouping all items.
   */
  async anchorBatch(hashes: string[], options: AnchorOptions = {}): Promise<BatchSubmission> {
    if (hashes.length === 0) return { submissionId: "", items: [] };
    if (hashes.length > 100) {
      throw new Error("anchorBatch: maximum 100 hashes per request");
    }
    const body: Record<string, unknown> = {
      hashes: hashes.map((h) => ({ hash: h, hash_algorithm: "SHA-256" })),
    };
    if (options.clientRef) body.client_ref = options.clientRef;
    if (options.description) body.description = options.description;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = await this.request<any>("POST", "/anchor/batch", body);
    return parseBatchSubmission(data);
  }

  /**
   * Return anchored/pending counts for a batch submission.
   */
  async getBatchStatus(submissionId: string): Promise<BatchStatus> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = await this.request<any>("GET", `/anchor/batch/${encodeURIComponent(submissionId)}/status`);
    return parseBatchStatus(data);
  }

  /**
   * Return all anchored inclusion proofs for a batch submission.
   */
  async getBatchProofs(submissionId: string): Promise<AnchorProof[]> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = await this.request<any>("GET", `/anchor/batch/${encodeURIComponent(submissionId)}/proofs`);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (data.proofs ?? []).map((p: any) => parseProof(p));
  }

  /**
   * Poll until all hashes in a batch submission are anchored, then return all proofs.
   * Accepts either a BatchSubmission object or a raw submission_id string.
   */
  async anchorBatchWait(
    submission: BatchSubmission | string,
    options: AnchorWaitOptions = {},
  ): Promise<AnchorProof[]> {
    const submissionId = typeof submission === "string" ? submission : submission.submissionId;
    const timeoutSecs = options.timeoutSecs ?? 900;
    const pollIntervalSecs = options.pollIntervalSecs ?? 15;
    const deadline = Date.now() + timeoutSecs * 1000;

    while (true) {
      const status = await this.getBatchStatus(submissionId);
      if (status.pending === 0 && status.total > 0) {
        return this.getBatchProofs(submissionId);
      }
      if (Date.now() >= deadline) {
        throw Object.assign(
          new Error(`anchorBatchWait timed out after ${timeoutSecs}s for submission ${submissionId}`),
          { name: "TimeoutError" },
        );
      }
      await new Promise((resolve) => setTimeout(resolve, pollIntervalSecs * 1000));
    }
  }

  /**
   * Retrieve a proof by tracking ID.
   * Returns null if the anchor is still pending (not yet included in a batch).
   */
  async getProof(trackingId: string): Promise<AnchorProof | null> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = await this.request<any>("GET", `/anchor/${encodeURIComponent(trackingId)}/proof`);
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

  // ── File helpers (Node.js only) ────────────────────────────────────────────

  /**
   * SHA-256 hash of a local file, returned as a lowercase hex string.
   * The file is never uploaded — only the digest is sent to the API.
   * Requires Node.js (uses node:fs/promises + node:crypto).
   */
  static async hashFile(path: string): Promise<string> {
    const buf = await readFile(path);
    return createHash("sha256").update(buf).digest("hex");
  }

  /**
   * Hash a local file with SHA-256 and submit it for anchoring.
   * `description` defaults to the filename if not provided.
   * Requires Node.js.
   */
  async anchorFile(path: string, options: AnchorOptions = {}): Promise<AnchorJob> {
    const hash = await TrustBeat.hashFile(path);
    const desc = options.description ?? basename(path);
    return this.anchor(hash, { ...options, description: desc });
  }

  /**
   * Hash a local file, submit for anchoring, and wait for the proof.
   * Convenience wrapper around anchorFile() + anchorWait().
   * Requires Node.js.
   */
  async anchorFileWait(
    path: string,
    options: AnchorOptions = {},
    waitOptions: AnchorWaitOptions = {},
  ): Promise<AnchorProof> {
    const job = await this.anchorFile(path, options);
    return this.anchorWait(job.id, waitOptions);
  }

  // ── AI Act Audit Anchoring ─────────────────────────────────────────────────

  /**
   * Submit an AI decision for EU AI Act Article 12 anchoring.
   *
   * Privacy-safe: only hashes are sent — raw model inputs and outputs are never uploaded.
   * Returns immediately with a tracking ID. Use getAiDecisionProof() or
   * anchorAiDecisionWait() to retrieve the proof once anchored (~10 minutes).
   */
  async anchorAiDecision(
    inputHash: string,
    outputHash: string,
    metadata: AiDecisionMetadata,
    options: { callbackUrl?: string } = {},
  ): Promise<AiDecisionJob> {
    const body: Record<string, unknown> = {
      input_hash: inputHash,
      output_hash: outputHash,
      metadata: {
        model_id: metadata.modelId,
        system_name: metadata.systemName,
        risk_category: metadata.riskCategory,
        decision_type: metadata.decisionType,
        human_oversight: metadata.humanOversight,
        time_envelope: {
          started_at: metadata.timeEnvelope.startedAt,
          completed_at: metadata.timeEnvelope.completedAt,
        },
        ...(metadata.modelVersion        ? { model_version:         metadata.modelVersion }        : {}),
        ...(metadata.operatorId          ? { operator_id:           metadata.operatorId }          : {}),
        ...(metadata.deploymentEnv       ? { deployment_env:        metadata.deploymentEnv }       : {}),
        ...(metadata.externalRef         ? { external_ref:          metadata.externalRef }         : {}),
        ...(metadata.decisionOutcome     ? { decision_outcome:      metadata.decisionOutcome }     : {}),
        ...(metadata.modelArtifactHash   ? { model_artifact_hash:   metadata.modelArtifactHash }   : {}),
        ...(metadata.dataSubjectCategory ? { data_subject_category: metadata.dataSubjectCategory } : {}),
      },
    };
    if (options.callbackUrl) body.callback_url = options.callbackUrl;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = await this.request<any>("POST", "/ai/decisions/anchor", body);
    return parseAiDecisionJob(data);
  }

  /**
   * Retrieve the verification result for a previously submitted AI decision.
   * Returns null if the decision is still pending (not yet anchored).
   * Throws NotFoundError if the tracking ID is unknown.
   */
  async getAiDecisionProof(trackingId: string): Promise<AiDecisionProof | null> {
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const data = await this.request<any>("GET", `/ai/decisions/verify/${encodeURIComponent(trackingId)}`);
      // Before anchoring the API returns 200 with verification_status "PENDING"
      // and no proof — treat that as "not ready yet" so pollers keep waiting.
      if (data.verification_status === "PENDING") return null;
      return parseAiDecisionProof(data);
    } catch (err) {
      if (err instanceof NotFoundError && err.code === "NOT_ANCHORED") return null;
      throw err;
    }
  }

  /**
   * Poll until the AI decision proof is ready, then return it.
   * Throws TimeoutError if not ready within timeoutSecs (default 660).
   */
  async anchorAiDecisionWait(
    trackingId: string,
    options: AnchorWaitOptions = {},
  ): Promise<AiDecisionProof> {
    const timeoutSecs = options.timeoutSecs ?? 660;
    const pollIntervalSecs = options.pollIntervalSecs ?? 15;
    const deadline = Date.now() + timeoutSecs * 1000;

    while (true) {
      const proof = await this.getAiDecisionProof(trackingId);
      if (proof !== null) return proof;
      if (Date.now() >= deadline) {
        throw Object.assign(
          new Error(`anchorAiDecisionWait timed out after ${timeoutSecs}s`),
          { name: "TimeoutError" },
        );
      }
      await new Promise((resolve) => setTimeout(resolve, pollIntervalSecs * 1000));
    }
  }

  // ── Signature & certificate verification ──────────────────────────────────

  /**
   * Verify eIDAS electronic signatures on a document.
   *
   * Validates PAdES (PDF), CAdES (CMS), or XAdES (XML) signatures against
   * the EU Trusted List. Returns a full report with per-signature details
   * and a top-level verdict.
   *
   * @param documentBytes - Raw document bytes.
   * @param format - Signature format: "pades" | "cades" | "xades".
   * @param callbackUrl - Optional webhook URL.
   */
  async verifySignature(
    documentBytes: Uint8Array | Buffer,
    format: "pades" | "cades" | "xades",
    options: { callbackUrl?: string } = {},
  ): Promise<VerificationReport> {
    const body: Record<string, unknown> = {
      document_base64: Buffer.from(documentBytes).toString("base64"),
      format,
    };
    if (options.callbackUrl) body.callback_url = options.callbackUrl;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = await this.request<any>("POST", "/verify/signature", body);
    return parseVerificationReport(data);
  }

  /**
   * Verify eIDAS signatures and anchor the verification event.
   *
   * Returns immediately (202 Accepted) with a tracking ID. The verification
   * event is queued for Merkle batch anchoring. Use getVerification() to
   * retrieve the completed report.
   *
   * @param documentBytes - Raw document bytes.
   * @param format - Signature format: "pades" | "cades" | "xades".
   * @param callbackUrl - Optional webhook URL called when anchoring completes.
   */
  async verifyAndAnchor(
    documentBytes: Uint8Array | Buffer,
    format: "pades" | "cades" | "xades",
    options: { callbackUrl?: string } = {},
  ): Promise<VerificationJob> {
    const body: Record<string, unknown> = {
      document_base64: Buffer.from(documentBytes).toString("base64"),
      format,
    };
    if (options.callbackUrl) body.callback_url = options.callbackUrl;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = await this.request<any>("POST", "/verify/signature/anchored", body);
    return parseVerificationJob(data);
  }

  /**
   * Retrieve a saved verification report by tracking ID.
   */
  async getVerification(trackingId: string): Promise<VerificationReport> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = await this.request<any>("GET", `/verify/${encodeURIComponent(trackingId)}`);
    return parseVerificationReport(data);
  }

  /**
   * Validate a standalone X.509 certificate against the EU Trusted List.
   *
   * @param certBytes - DER- or PEM-encoded certificate bytes.
   */
  async validateCertificate(certBytes: Uint8Array | Buffer): Promise<CertificateValidationResult> {
    const body = { certificate_base64: Buffer.from(certBytes).toString("base64") };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = await this.request<any>("POST", "/validate/certificate", body);
    return parseCertValidationResult(data);
  }

  // ── Audit Trail ─────────────────────────────────────────────────────────────

  /**
   * Submit a single audit event for tamper-evident Merkle anchoring.
   * Returns the `eventId` immediately (202 Accepted).
   */
  async submitAuditEvent(params: {
    trailCategory: string;
    actor: string;
    action: string;
    ts: string;
    system?: string;
    subsystem?: string;
    resource?: string;
    subresource?: string;
    metadata?: Record<string, unknown>;
    clientRef1?: string;
    clientRef2?: string;
    clientRef3?: string;
    clientRef4?: string;
    clientRef5?: string;
  }): Promise<string> {
    const body: Record<string, unknown> = {
      trail_category: params.trailCategory,
      actor:          params.actor,
      action:         params.action,
      ts:             params.ts,
    };
    if (params.system)      body.system      = params.system;
    if (params.subsystem)   body.subsystem   = params.subsystem;
    if (params.resource)    body.resource    = params.resource;
    if (params.subresource) body.subresource = params.subresource;
    if (params.metadata)    body.metadata    = params.metadata;
    if (params.clientRef1)  body.client_ref_1 = params.clientRef1;
    if (params.clientRef2)  body.client_ref_2 = params.clientRef2;
    if (params.clientRef3)  body.client_ref_3 = params.clientRef3;
    if (params.clientRef4)  body.client_ref_4 = params.clientRef4;
    if (params.clientRef5)  body.client_ref_5 = params.clientRef5;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = await this.request<any>("POST", "/audit/events", body);
    return data.event_id as string;
  }

  /**
   * Submit up to 1,000 audit events in a single batch request.
   * Returns the list of `eventId` strings in submission order.
   */
  async submitAuditEvents(events: Array<Record<string, unknown>>): Promise<string[]> {
    // The API decodes the body as a bare JSON array of events — do NOT wrap it
    // in an object.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = await this.request<any>("POST", "/audit/events/batch", events);
    return (data.event_ids ?? []) as string[];
  }

  /**
   * Fetch the Merkle inclusion proof for an anchored audit event.
   * Returns `null` if the event exists but is not yet anchored.
   */
  async getAuditEventProof(eventId: string): Promise<AuditEventProof | null> {
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const data = await this.request<any>("GET", `/audit/events/${eventId}/proof`);
      if (data.status === "pending") return null;
      return parseAuditEventProof(data);
    } catch (err) {
      if (err instanceof NotFoundError) throw err;
      return null;
    }
  }

  /**
   * Query audit events with optional filters. Returns one page of results.
   */
  async listAuditEvents(params?: {
    trailCategory?: string;
    actor?: string;
    action?: string;
    resource?: string;
    system?: string;
    from?: string;
    to?: string;
    page?: number;
    pageSize?: number;
  }): Promise<AuditEvent[]> {
    const p = params ?? {};
    const qs = new URLSearchParams();
    if (p.trailCategory) qs.set("trail_category", p.trailCategory);
    if (p.actor)         qs.set("actor",          p.actor);
    if (p.action)        qs.set("action",         p.action);
    if (p.resource)      qs.set("resource",       p.resource);
    if (p.system)        qs.set("system",         p.system);
    if (p.from)          qs.set("from",           p.from);
    if (p.to)            qs.set("to",             p.to);
    qs.set("page",      String(p.page     ?? 1));
    qs.set("page_size", String(p.pageSize ?? 25));
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = await this.request<any>("GET", `/audit/events?${qs}`);
    return (data.events ?? []).map(parseAuditEvent);
  }

  /**
   * Export audit events as a court-admissible ZIP and return the raw bytes.
   * Blocks until the export job completes (polls every 3 s, up to 5 min).
   */
  async exportAuditEvents(params: {
    from: string;
    to: string;
    trailCategory?: string;
  }): Promise<Uint8Array> {
    if (!params?.from || !params?.to) {
      throw new TrustBeatError("exportAuditEvents requires both from and to");
    }
    const body: Record<string, string> = { from: params.from, to: params.to };
    if (params.trailCategory) body.trail_category = params.trailCategory;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const jobData = await this.request<any>("POST", "/audit/export", body);
    const jobId: string = jobData.job_id;
    const deadline = Date.now() + 300_000;
    while (true) {
      const res = await fetch(`${this.baseUrl}/audit/export/${jobId}`, {
        headers: { Authorization: `Bearer ${this.apiKey}` },
      });
      if (!res.ok) throw new TrustBeatError(`Export poll failed: HTTP ${res.status}`);
      const ct = res.headers.get("content-type") ?? "";
      if (ct.startsWith("application/zip")) {
        return new Uint8Array(await res.arrayBuffer());
      }
      const status = (await res.json() as AuditExportJob);
      if (status.status === "failed") throw new TrustBeatError(status.error ?? "Export failed");
      if (Date.now() > deadline) throw new TrustBeatError(`Export job ${jobId} timed out`);
      await new Promise(r => setTimeout(r, 3000));
    }
  }

  // ── Tamper-Evident Logs (NIS2) ─────────────────────────────────────────────

  /**
   * Submit a log hash for NIS2 Article 21 tamper-evident anchoring. Returns
   * immediately (202) with a tracking ID; the log is anchored in the next batch
   * (~10 min). The server binds `metadata` into the Merkle leaf.
   */
  async anchorLog(
    logHash: string,
    metadata: LogMetadata,
    options: { label?: string } = {},
  ): Promise<LogAnchorJob> {
    const body: Record<string, unknown> = { log_hash: logHash, metadata: logMetadataToJson(metadata) };
    if (options.label !== undefined) body.label = options.label;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = await this.request<any>("POST", "/logs/anchor", body);
    return parseLogAnchorJob(data);
  }

  /**
   * Fetch the verification result for a log anchor. Returns `null` while the log
   * is still pending (verification_status "PENDING"). Throws NotFoundError if the
   * tracking ID is unknown.
   */
  async getLogProof(trackingId: string): Promise<LogProof | null> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = await this.request<any>("GET", `/logs/verify/${encodeURIComponent(trackingId)}`);
    if (data.verification_status === "PENDING") return null;
    return parseLogProof(data);
  }

  /** Get the lightweight status of a log anchor submission (cheap polling). */
  async getLogStatus(trackingId: string): Promise<LogStatus> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = await this.request<any>("GET", `/logs/${encodeURIComponent(trackingId)}/status`);
    return parseLogStatus(data);
  }

  /** List recent log anchor submissions, with optional filters. */
  async listLogs(params?: {
    status?: "pending" | "anchored";
    from?: string;
    to?: string;
  }): Promise<LogAnchorListItem[]> {
    const qs = new URLSearchParams();
    if (params?.status) qs.set("status", params.status);
    if (params?.from)   qs.set("from", params.from);
    if (params?.to)     qs.set("to", params.to);
    const suffix = qs.toString() ? `?${qs}` : "";
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = await this.request<any>("GET", `/logs${suffix}`);
    return (data.logs ?? []).map(parseLogAnchorListItem);
  }

  /**
   * Download a portable NIS2 log proof bundle (bundle_type "trustbeat.log.proof").
   * Returns the raw JSON bundle bytes. Throws NotFoundError if unknown/not anchored.
   */
  async exportLog(trackingId: string): Promise<Uint8Array> {
    const res = await fetch(`${this.baseUrl}/logs/${encodeURIComponent(trackingId)}/export`, {
      headers: { Authorization: `Bearer ${this.apiKey}`, Accept: "application/json" },
    });
    if (res.status === 404) throw new NotFoundError(`Log ${trackingId} not found`);
    if (!res.ok) throw new TrustBeatError(`Log export failed: HTTP ${res.status}`, res.status);
    return new Uint8Array(await res.arrayBuffer());
  }

  /**
   * Poll getLogProof() until the log is anchored, then return the proof.
   * Throws TimeoutError if not ready within timeoutSecs (default 660).
   */
  async anchorLogWait(
    trackingId: string,
    options: AnchorWaitOptions = {},
  ): Promise<LogProof> {
    const timeoutSecs = options.timeoutSecs ?? 660;
    const pollIntervalSecs = options.pollIntervalSecs ?? 15;
    const deadline = Date.now() + timeoutSecs * 1000;
    while (true) {
      const proof = await this.getLogProof(trackingId);
      if (proof !== null) return proof;
      if (Date.now() >= deadline) {
        throw Object.assign(
          new Error(`anchorLogWait timed out after ${timeoutSecs}s`),
          { name: "TimeoutError" },
        );
      }
      await new Promise((resolve) => setTimeout(resolve, pollIntervalSecs * 1000));
    }
  }

}
