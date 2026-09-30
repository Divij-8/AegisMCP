/**
 * Row ↔ domain mappers. Mapping rules live here so pg implementations stay
 * thin and the domain types stay DB-agnostic.
 *
 * Mappers throw on rows that violate domain invariants — the callers
 * (PolicyStore validation / startup) turn that into fail-closed behavior.
 */

import type { AgentIdentity, ServerIdentity } from "../security/identity.js";
import type { Policy, PolicyDecision, PolicyMatch } from "../policy/types.js";
import type {
  AuditEvent,
  AuditEventType,
  AuditOutcome,
  AuthFailureReason,
} from "../audit/types.js";
import type { AgentCredentialRecord } from "./types.js";

const DECISIONS: readonly PolicyDecision[] = ["ALLOW", "DENY", "REQUIRE_APPROVAL"];
const EVENT_TYPES: readonly AuditEventType[] = ["request", "notification", "auth"];
const OUTCOMES: readonly AuditOutcome[] = ["blocked", "forwarded", "upstream_error", "auth_failed"];
const AUTH_FAILURE_REASONS: readonly AuthFailureReason[] = [
  "missing",
  "malformed",
  "unknown",
  "revoked",
  "expired",
  "invalid",
  "error",
];

function asString(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new Error(`Invalid row: ${field} must be a string`);
  }
  return value;
}

function asOptionalString(value: unknown, field: string): string | undefined {
  if (value === null || value === undefined) return undefined;
  return asString(value, field);
}

function asNullableNumber(value: unknown, field: string): number | null {
  if (value === null || value === undefined) return null;
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`Invalid row: ${field} must be a number`);
  }
  return value;
}

/** Accepts a pg timestamptz (Date) or an ISO string and returns epoch millis. */
function toEpochMillis(value: unknown, field: string): number {
  if (value instanceof Date) return value.getTime();
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string") {
    const parsed = Date.parse(value);
    if (!Number.isNaN(parsed)) return parsed;
  }
  throw new Error(`Invalid row: ${field} must be a timestamp`);
}

function toNullableEpochMillis(value: unknown, field: string): number | null {
  if (value === null || value === undefined) return null;
  return toEpochMillis(value, field);
}

export function toDomainAgent(row: Record<string, unknown>): AgentIdentity {
  return Object.freeze({
    id: asString(row["id"], "id"),
    name: asString(row["name"], "name"),
  });
}

export function toDomainServer(row: Record<string, unknown>): ServerIdentity {
  return Object.freeze({
    id: asString(row["id"], "id"),
    name: asString(row["name"], "name"),
    upstreamUrl: asString(row["upstream_url"], "upstream_url"),
  });
}

export function toDomainPolicy(row: Record<string, unknown>): Policy {
  const id = asString(row["id"], "id");
  const decision = asString(row["decision"], "decision") as PolicyDecision;
  if (!DECISIONS.includes(decision)) {
    throw new Error(`Invalid row: policy "${id}" has unknown decision "${decision}"`);
  }

  const rawMatch = row["match"];
  if (typeof rawMatch !== "object" || rawMatch === null || Array.isArray(rawMatch)) {
    throw new Error(`Invalid row: policy "${id}" match must be an object`);
  }
  const raw = rawMatch as Record<string, unknown>;
  const match: PolicyMatch = {
    ...(raw["agent"] !== undefined && raw["agent"] !== null
      ? { agent: asString(raw["agent"], "match.agent") }
      : {}),
    ...(raw["server"] !== undefined && raw["server"] !== null
      ? { server: asString(raw["server"], "match.server") }
      : {}),
    ...(raw["method"] !== undefined && raw["method"] !== null
      ? { method: asString(raw["method"], "match.method") }
      : {}),
    ...(raw["tool"] !== undefined && raw["tool"] !== null
      ? { tool: asString(raw["tool"], "match.tool") }
      : {}),
  };

  const reason = asString(row["reason"], "reason");
  if (reason.trim() === "") {
    throw new Error(`Invalid row: policy "${id}" reason must be non-empty`);
  }

  const priority = asNullableNumber(row["priority"], "priority");
  const enabled = row["enabled"];

  return Object.freeze({
    id,
    decision,
    match,
    reason,
    ...(priority !== null && priority !== 0 ? { priority } : {}),
    ...(enabled === false ? { enabled: false } : {}),
  });
}

export function toDomainAgentCredential(row: Record<string, unknown>): AgentCredentialRecord {
  return Object.freeze({
    keyId: asString(row["key_id"], "key_id"),
    agent: Object.freeze({
      id: asString(row["agent_id"], "agent_id"),
      name: asString(row["agent_name"], "agent_name"),
    }),
    label: asOptionalString(row["label"], "label"),
    secretHash: asString(row["secret_hash"], "secret_hash"),
    salt: asString(row["salt"], "salt"),
    hashAlgo: asString(row["hash_algo"], "hash_algo"),
    createdAt: toEpochMillis(row["created_at"], "created_at"),
    expiresAt: toNullableEpochMillis(row["expires_at"], "expires_at"),
    revokedAt: toNullableEpochMillis(row["revoked_at"], "revoked_at"),
  });
}

export function toDomainAuditEvent(row: Record<string, unknown>): AuditEvent {
  const eventType = asString(row["event_type"], "event_type") as AuditEventType;
  if (!EVENT_TYPES.includes(eventType)) {
    throw new Error(`Invalid row: unknown event_type "${eventType}"`);
  }

  const outcome = asString(row["outcome"], "outcome") as AuditOutcome;
  if (!OUTCOMES.includes(outcome)) {
    throw new Error(`Invalid row: unknown outcome "${outcome}"`);
  }

  const decisionRaw = asOptionalString(row["decision"], "decision");
  if (decisionRaw !== undefined && !DECISIONS.includes(decisionRaw as PolicyDecision)) {
    throw new Error(`Invalid row: unknown decision "${decisionRaw}"`);
  }

  const latency = asNullableNumber(row["latency_ms"], "latency_ms");
  if (latency === null) {
    throw new Error("Invalid row: latency_ms is required");
  }

  const hash = asOptionalString(row["tool_args_hash"], "tool_args_hash");
  const hashAlgo = asOptionalString(row["tool_args_hash_algo"], "tool_args_hash_algo");

  const authFailureReasonRaw = asOptionalString(row["auth_failure_reason"], "auth_failure_reason");
  if (
    authFailureReasonRaw !== undefined &&
    !AUTH_FAILURE_REASONS.includes(authFailureReasonRaw as AuthFailureReason)
  ) {
    throw new Error(`Invalid row: unknown auth_failure_reason "${authFailureReasonRaw}"`);
  }

  const keyId = asOptionalString(row["key_id"], "key_id");

  return {
    eventType,
    requestId: (row["request_id"] as string | null) ?? null,
    occurredAt: toEpochMillis(row["occurred_at"], "occurred_at"),
    agentId: asOptionalString(row["agent_id"], "agent_id") ?? null,
    serverId: asString(row["server_id"], "server_id"),
    method: asString(row["method"], "method"),
    toolName: asOptionalString(row["tool_name"], "tool_name"),
    decision: (decisionRaw as PolicyDecision | undefined) ?? null,
    policyId: asOptionalString(row["policy_id"], "policy_id") ?? null,
    reason: asString(row["reason"], "reason"),
    outcome,
    upstreamStatus: asNullableNumber(row["upstream_status"], "upstream_status"),
    latencyMs: latency,
    ...(keyId !== undefined ? { keyId } : {}),
    ...(authFailureReasonRaw !== undefined
      ? { authFailureReason: authFailureReasonRaw as AuthFailureReason }
      : {}),
    ...(hash !== undefined && hashAlgo !== undefined
      ? { toolArgumentsRedaction: { hash, algorithm: hashAlgo } }
      : {}),
  };
}
