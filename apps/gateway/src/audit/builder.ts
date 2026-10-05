/**
 * Audit event construction — pure functions from SecurityContext,
 * PolicyEvaluation, and transport outcomes to AuditEvent data.
 */

import type { AuditEvent, AuditEventType, AuditOutcome, AuthFailureReason } from "./types.js";
import type { SecurityContext } from "../mcp/types.js";
import type { PolicyEvaluation } from "../policy/types.js";
import type { ApprovalRecord } from "../approvals/types.js";
import type { RiskLevel } from "../risk/types.js";

export interface NotificationAuditInput {
  /** Notification method (e.g. "notifications/cancelled"). */
  readonly method: string;
  readonly occurredAt: number;
  readonly agentId: string;
  readonly serverId: string;
  readonly outcome: AuditOutcome;
  readonly latencyMs: number;
}

export function buildRequestAuditEvent(input: {
  context: SecurityContext;
  evaluation: PolicyEvaluation;
  outcome: AuditOutcome;
  upstreamStatus: number | null;
  latencyMs: number;
  /** Public approval id when the request was gated on (or used) an approval. */
  approvalId?: string;
  /** Risk level computed after policy evaluation. */
  riskLevel?: RiskLevel;
}): AuditEvent {
  const { context, evaluation, outcome, upstreamStatus, latencyMs } = input;
  return {
    eventType: "request",
    requestId: context.requestId,
    occurredAt: context.timestamp,
    agentId: context.agent.id,
    serverId: context.server.id,
    method: context.method,
    toolName: context.toolName,
    decision: evaluation.decision,
    policyId: evaluation.policyId,
    reason: evaluation.reason,
    outcome,
    upstreamStatus,
    latencyMs,
    ...(input.approvalId !== undefined ? { approvalId: input.approvalId } : {}),
    ...(input.riskLevel !== undefined ? { riskLevel: input.riskLevel } : {}),
  };
}

/**
 * Build an audit event for a control-plane operation.
 *
 * `action` is a stable verb such as "policy.create" or "approval.approve".
 * The actor is the authenticated administrator; no request body is recorded.
 */
export function buildAdminAuditEvent(input: {
  action: string;
  outcome: "forwarded" | "blocked";
  actorId: string;
  serverId: string;
  occurredAt: number;
  latencyMs: number;
  detail?: string;
}): AuditEvent {
  return {
    eventType: "admin",
    requestId: null,
    occurredAt: input.occurredAt,
    agentId: input.actorId,
    serverId: input.serverId,
    method: `admin.${input.action}`,
    toolName: undefined,
    decision: null,
    policyId: null,
    reason:
      input.detail === undefined
        ? `admin ${input.action}`
        : `admin ${input.action}: ${input.detail}`,
    outcome: input.outcome,
    upstreamStatus: null,
    latencyMs: input.latencyMs,
  };
}

/**
 * Build an audit event for one step of the approval lifecycle.
 *
 * These events never contain tool arguments or arguments hashes — only the
 * public approval id, the identities involved, and the decision.
 */
export function buildApprovalAuditEvent(
  eventType: Extract<AuditEventType, `approval_${string}`>,
  record: ApprovalRecord,
): AuditEvent {
  const outcome: AuditOutcome =
    eventType === "approval_created" || eventType === "approval_approved" ? "pending" : "blocked";

  const reasonByType: Record<string, string> = {
    approval_created: `Approval required: ${record.reason}`,
    approval_approved: `Approval ${record.id} approved by ${record.approverId ?? "unknown"}`,
    approval_denied: `Approval ${record.id} denied by ${record.approverId ?? "unknown"}`,
    approval_expired: `Approval ${record.id} expired without a decision`,
  };
  const reason = reasonByType[eventType] ?? `Approval ${record.id} ${eventType}`;
  const reasonWithNote =
    eventType === "approval_denied" && record.decisionReason !== null
      ? `${reason}: ${record.decisionReason}`
      : reason;

  return {
    eventType,
    requestId: record.requestId,
    occurredAt: record.decidedAt ?? record.createdAt,
    agentId: record.agentId,
    serverId: record.serverId,
    method: record.method,
    toolName: record.toolName,
    decision: "REQUIRE_APPROVAL",
    policyId: record.policyId,
    reason: reasonWithNote,
    outcome,
    upstreamStatus: null,
    latencyMs: 0,
    approvalId: record.id,
  };
}

export function buildNotificationAuditEvent(input: NotificationAuditInput): AuditEvent {
  return {
    eventType: "notification",
    requestId: null,
    occurredAt: input.occurredAt,
    agentId: input.agentId,
    serverId: input.serverId,
    method: input.method,
    toolName: undefined,
    decision: null,
    policyId: null,
    reason: "notification — bypasses authorization by design",
    outcome: input.outcome,
    upstreamStatus: null,
    latencyMs: input.latencyMs,
  };
}

export interface AuthFailureAuditInput {
  /** JSON-RPC id when the body parsed; null for notifications / unparseable ids. */
  readonly requestId: string | number | null;
  /** Method when known, otherwise "unknown". */
  readonly method: string;
  readonly occurredAt: number;
  /** Trusted server identity — always known, independent of the caller. */
  readonly serverId: string;
  /** Public key id when one could be parsed; null otherwise. Never the secret. */
  readonly keyId: string | null;
  readonly failureReason: AuthFailureReason;
  readonly latencyMs: number;
}

/**
 * Human-readable audit reasons. These are deliberately detailed for operators
 * but never include credential material — client responses are generic.
 */
const AUTH_FAILURE_REASONS: Record<AuthFailureReason, string> = {
  missing: "Authentication failed: no credential presented",
  malformed: "Authentication failed: malformed credential",
  unknown: "Authentication failed: unknown credential",
  revoked: "Authentication failed: revoked credential",
  expired: "Authentication failed: expired credential",
  invalid: "Authentication failed: invalid credential secret",
  error: "Authentication failed: credential store unavailable",
};

/**
 * Build an audit event for a failed authentication attempt.
 *
 * agentId is always null: an authentication failure means no agent was
 * resolved. The audit row records only the PUBLIC key id, never the secret.
 */
export function buildAuthFailureAuditEvent(input: AuthFailureAuditInput): AuditEvent {
  return {
    eventType: "auth",
    requestId: input.requestId,
    occurredAt: input.occurredAt,
    agentId: null,
    serverId: input.serverId,
    method: input.method,
    toolName: undefined,
    decision: null,
    policyId: null,
    reason: AUTH_FAILURE_REASONS[input.failureReason],
    outcome: "auth_failed",
    upstreamStatus: null,
    latencyMs: input.latencyMs,
    ...(input.keyId !== null ? { keyId: input.keyId } : {}),
    authFailureReason: input.failureReason,
  };
}
