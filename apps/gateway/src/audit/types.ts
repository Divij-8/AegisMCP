/**
 * Audit domain types — transport-independent, DB-agnostic.
 *
 * An AuditEvent is pure data. It never contains raw tool arguments: the
 * optional redaction field is a slot for future hashing/redaction and is
 * left undefined by the gateway today.
 */

import type { PolicyDecision } from "../policy/types.js";
import type { RiskLevel } from "../risk/types.js";

/** What kind of MCP message produced this event. */
export type AuditEventType =
  /** An actionable MCP request. */
  | "request"
  /** An MCP notification. */
  | "notification"
  /** An authentication gate outcome (Phase 5). */
  | "auth"
  /** A control-plane (administrative) operation. */
  | "admin"
  /** A REQUIRE_APPROVAL decision created a PENDING approval. */
  | "approval_created"
  /** An administrator approved a pending approval. */
  | "approval_approved"
  /** An administrator denied a pending approval. */
  | "approval_denied"
  /** A pending approval passed its expiry without a decision. */
  | "approval_expired";

/** Terminal outcome of the gateway's handling of the message. */
export type AuditOutcome =
  /** Blocked before proxying (DENY, REQUIRE_APPROVAL, or unsupported protocol). */
  | "blocked"
  /** Forwarded upstream; upstream produced a response status. */
  | "forwarded"
  /** Forwarding failed before an upstream status existed (502/504). */
  | "upstream_error"
  /** Rejected by the authentication gate before policy evaluation. */
  | "auth_failed"
  /** Awaiting a human decision; nothing has executed and nothing has failed. */
  | "pending";

/**
 * Precise internal reason an authentication attempt failed.
 *
 * This taxonomy is persisted in audit_events.auth_failure_reason and is
 * deliberately MORE detailed than what clients see: client responses stay
 * generic so the gateway never becomes a credential-enumeration oracle.
 */
export type AuthFailureReason =
  /** No credential was presented. */
  | "missing"
  /** A credential was presented but is not a well-formed API key. */
  | "malformed"
  /** The public key id is not present in the credential store. */
  | "unknown"
  /** The credential was explicitly revoked. */
  | "revoked"
  /** The credential is past its expiry. */
  | "expired"
  /** The credential exists but the secret did not verify. */
  | "invalid"
  /** The credential store could not be consulted (infrastructure failure). */
  | "error";

/**
 * Reserved slot for future argument redaction/hashing.
 * Never populated by default — see schema tool_args_hash columns.
 */
export interface ToolArgumentsRedaction {
  /** Digest of the serialized arguments (e.g. hex sha-256). */
  readonly hash: string;
  /** Algorithm identifier, e.g. "sha256". */
  readonly algorithm: string;
}

export interface AuditEvent {
  /** request | notification — explicit, not inferred from nullability. */
  readonly eventType: AuditEventType;
  /** JSON-RPC id; null for notifications. */
  readonly requestId: string | number | null;
  /** Gateway-local epoch millis when the message was received. */
  readonly occurredAt: number;
  /**
   * Authenticated agent. Null ONLY for authentication failures that occur
   * before any agent is known (missing/malformed/unknown credential).
   */
  readonly agentId: string | null;
  readonly serverId: string;
  readonly method: string;
  /** Tool name for tools/call; undefined otherwise. */
  readonly toolName: string | undefined;
  /** Decision for actionable requests; null for notifications. */
  readonly decision: PolicyDecision | null;
  /** Matching policy id, or null for default decision / notifications. */
  readonly policyId: string | null;
  /** Human-readable reason — always non-empty. */
  readonly reason: string;
  readonly outcome: AuditOutcome;
  /** Upstream HTTP status when outcome is forwarded; null otherwise. */
  readonly upstreamStatus: number | null;
  readonly latencyMs: number;
  /**
   * Public key id of the presented credential for auth events.
   * NEVER the secret — this is the same non-secret lookup identifier that is
   * stored in agent_credentials.key_id.
   */
  readonly keyId?: string;
  /** Set for event_type "auth" only. */
  readonly authFailureReason?: AuthFailureReason;
  /**
   * Public approval id for approval-lifecycle events and for requests that were
   * gated on an approval. Never secret material.
   */
  readonly approvalId?: string;
  /** Risk level computed after policy evaluation (Phase 5). */
  readonly riskLevel?: RiskLevel;
  /** Future slot — never set today. */
  readonly toolArgumentsRedaction?: ToolArgumentsRedaction;
}

/**
 * Where audit events go. Implementations: DbAuditSink (buffered PostgreSQL)
 * and InMemoryAuditSink (tests). record() must never block the request path.
 */
export interface AuditSink {
  /** Enqueue an event. Synchronous, non-blocking, never throws. */
  record(event: AuditEvent): void;
  /** Await delivery of all queued events (shutdown / tests). */
  flush(): Promise<void>;
  /** Stop background flushing and release resources. */
  close(): Promise<void>;
  /** Point-in-time counters for metrics/observability. */
  stats(): AuditSinkStats;
}

export interface AuditSinkStats {
  /** Events currently buffered, waiting to be flushed. */
  readonly queued: number;
  /** Events successfully persisted. */
  readonly flushed: number;
  /** Events dropped because persistence failed (after retries). */
  readonly failed: number;
  /** Events dropped due to queue overflow (oldest dropped first). */
  readonly dropped: number;
}
