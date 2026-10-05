/**
 * Approval domain types — transport-independent and DB-agnostic.
 *
 * An approval represents a REQUIRE_APPROVAL policy decision that is waiting for
 * (or has received) a human decision. It is created from the ORIGINAL security
 * context and is bound to it by (agentId, serverId, method, toolName, argsHash),
 * so a different request can never reuse it.
 *
 * Security invariants:
 * - Only REDACTED arguments are ever stored. Raw arguments never reach the DB.
 * - `argsHash` binds an approval to the exact request; it is not a secret, but
 *   it is never populated from redacted values.
 * - Approvals are single-use (consumedAt) and always expire.
 */

export type ApprovalStatus = "PENDING" | "APPROVED" | "DENIED" | "EXPIRED";

/** All statuses that represent a final, non-actionable state. */
export const TERMINAL_APPROVAL_STATUSES: readonly ApprovalStatus[] = [
  "APPROVED",
  "DENIED",
  "EXPIRED",
];

/** Fields that uniquely bind an approval to the request it was created for. */
export interface ApprovalBinding {
  readonly agentId: string;
  readonly serverId: string;
  readonly method: string;
  readonly toolName: string | undefined;
  /** Digest of the exact (unredacted) tool arguments. */
  readonly argsHash: string;
  readonly argsHashAlgo: string;
}

/** A persisted approval. `arguments` holds ONLY redacted values. */
export interface ApprovalRecord extends ApprovalBinding {
  readonly id: string;
  readonly requestId: string | number | null;
  /** Redacted tool arguments, safe to persist and display. */
  readonly arguments: Record<string, unknown>;
  readonly policyId: string | null;
  readonly decision: "REQUIRE_APPROVAL";
  readonly reason: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly status: ApprovalStatus;
  /** Agent id of the deciding administrator; null while PENDING. */
  readonly approverId: string | null;
  readonly decidedAt: number | null;
  readonly decisionReason: string | null;
  /** Set exactly once, when the approval is actually executed. */
  readonly consumedAt: number | null;
}

/** Input for creating a PENDING approval. */
export interface NewApproval extends ApprovalBinding {
  readonly id: string;
  readonly requestId: string | number | null;
  readonly arguments: Record<string, unknown>;
  readonly policyId: string | null;
  readonly reason: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

/** Query filter for listing approvals. */
export interface ApprovalListFilter {
  readonly status?: ApprovalStatus;
  readonly agentId?: string;
  readonly serverId?: string;
}
