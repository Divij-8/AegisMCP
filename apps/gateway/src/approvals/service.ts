/**
 * Approval workflow service — the ONLY place approval state transitions happen.
 *
 * Lifecycle:
 *   REQUIRE_APPROVAL → PENDING → APPROVED | DENIED | EXPIRED
 *   APPROVED + correct binding + not expired + not consumed → executed once
 *
 * Invariants (all fail-closed):
 * - Without a repository (persistence disabled) nothing can be created, decided,
 *   expired, or consumed — the gateway can never treat an approval as granted.
 * - A PENDING approval never authorizes execution; only consume() on an APPROVED,
 *   unexpired, unconsumed approval bound to the EXACT request does.
 * - Expired approvals can be neither approved nor executed.
 * - An approval is single-use: consume() flips consumed_at atomically, so a
 *   replay loses the race and is refused.
 * - Every lifecycle transition is audited.
 */

import { randomBytes } from "node:crypto";
import type { SecurityContext } from "../mcp/types.js";
import type { PolicyEvaluation } from "../policy/types.js";
import type { AuditSink } from "../audit/types.js";
import type { ApprovalRepository, Page, PageQuery } from "../repositories/types.js";
import type { ApprovalBinding, ApprovalListFilter, ApprovalRecord } from "./types.js";
import { hashArguments, redactArguments, ARGS_HASH_ALGORITHM } from "./redact.js";
import { buildApprovalAuditEvent } from "../audit/builder.js";

export const DEFAULT_APPROVAL_TTL_MS = 15 * 60 * 1000;
export const MAX_APPROVAL_TTL_MS = 24 * 60 * 60 * 1000;

export interface ApprovalServiceOptions {
  readonly defaultTtlMs?: number;
  readonly maxTtlMs?: number;
  readonly now?: () => number;
  readonly idFactory?: () => string;
}

export type CreateApprovalResult =
  | { readonly kind: "created"; readonly approval: ApprovalRecord }
  | { readonly kind: "existing"; readonly approval: ApprovalRecord }
  | { readonly kind: "unavailable" };

export type DecideKind = "approved" | "denied" | "not_found" | "expired" | "already_decided";

export type DecideResult =
  | { readonly kind: "approved" | "denied"; readonly approval: ApprovalRecord }
  | { readonly kind: "expired" | "already_decided"; readonly approval: ApprovalRecord }
  | { readonly kind: "not_found" };

export type ConsumeKind =
  "ok" | "not_found" | "expired" | "not_approved" | "already_consumed" | "binding_mismatch";

export type ConsumeResult =
  | { readonly kind: "ok"; readonly approval: ApprovalRecord }
  | { readonly kind: Exclude<ConsumeKind, "ok">; readonly approval: ApprovalRecord }
  | { readonly kind: "not_found" };

function defaultIdFactory(): string {
  return `apr_${randomBytes(16).toString("hex")}`;
}

function bindingOf(context: SecurityContext): ApprovalBinding {
  return {
    agentId: context.agent.id,
    serverId: context.server.id,
    method: context.method,
    toolName: context.toolName,
    argsHash: hashArguments(context.toolArguments),
    argsHashAlgo: ARGS_HASH_ALGORITHM,
  };
}

function sameBinding(a: ApprovalBinding, b: ApprovalBinding): boolean {
  return (
    a.agentId === b.agentId &&
    a.serverId === b.serverId &&
    a.method === b.method &&
    a.toolName === b.toolName &&
    a.argsHash === b.argsHash &&
    a.argsHashAlgo === b.argsHashAlgo
  );
}

export class ApprovalService {
  private readonly now: () => number;
  private readonly idFactory: () => string;
  private readonly defaultTtlMs: number;
  private readonly maxTtlMs: number;

  constructor(
    private readonly repository: ApprovalRepository | null,
    private readonly auditSink: AuditSink,
    options: ApprovalServiceOptions = {},
  ) {
    this.now = options.now ?? Date.now;
    this.idFactory = options.idFactory ?? defaultIdFactory;
    this.defaultTtlMs = options.defaultTtlMs ?? DEFAULT_APPROVAL_TTL_MS;
    this.maxTtlMs = options.maxTtlMs ?? MAX_APPROVAL_TTL_MS;
  }

  /** True when approvals can actually be persisted (persistence enabled). */
  get available(): boolean {
    return this.repository !== null;
  }

  private clampTtl(ttlMs: number | undefined): number {
    const requested = ttlMs ?? this.defaultTtlMs;
    if (!Number.isFinite(requested) || requested <= 0) return this.defaultTtlMs;
    return Math.min(requested, this.maxTtlMs);
  }

  /**
   * Create (or reuse) the PENDING approval for a REQUIRE_APPROVAL decision.
   * Reusing an existing PENDING approval for the exact same binding keeps
   * retries from flooding the queue.
   */
  async createForContext(
    context: SecurityContext,
    evaluation: PolicyEvaluation,
    ttlMs?: number,
  ): Promise<CreateApprovalResult> {
    if (this.repository === null) return { kind: "unavailable" };

    const binding = bindingOf(context);
    const existing = await this.repository.findPendingByBinding(binding);
    if (existing !== null) return { kind: "existing", approval: existing };

    const createdAt = this.now();
    const expiresAt = createdAt + this.clampTtl(ttlMs);

    const record: ApprovalRecord = Object.freeze({
      id: this.idFactory(),
      requestId: context.requestId,
      ...binding,
      arguments: Object.freeze(redactArguments(context.toolArguments) ?? {}),
      policyId: evaluation.policyId,
      decision: "REQUIRE_APPROVAL",
      reason: evaluation.reason,
      createdAt,
      expiresAt,
      status: "PENDING",
      approverId: null,
      decidedAt: null,
      decisionReason: null,
      consumedAt: null,
    });

    try {
      await this.repository.create(record);
    } catch (error) {
      // Unique-index race: another request created the same PENDING approval.
      const raced = await this.repository.findPendingByBinding(binding);
      if (raced !== null) return { kind: "existing", approval: raced };
      throw error;
    }

    this.auditSink.record(buildApprovalAuditEvent("approval_created", record));
    return { kind: "created", approval: record };
  }

  async getById(id: string): Promise<ApprovalRecord | null> {
    if (this.repository === null) return null;
    return this.repository.findById(id);
  }

  async list(filter: ApprovalListFilter, page: PageQuery): Promise<Page<ApprovalRecord>> {
    if (this.repository === null) {
      return { items: [], total: 0, limit: page.limit, offset: page.offset };
    }
    return this.repository.list(filter, page);
  }

  async approve(id: string, approverId: string, reason?: string): Promise<DecideResult> {
    return this.decide(id, "APPROVED", approverId, reason);
  }

  async deny(id: string, approverId: string, reason?: string): Promise<DecideResult> {
    return this.decide(id, "DENIED", approverId, reason);
  }

  private async decide(
    id: string,
    status: "APPROVED" | "DENIED",
    approverId: string,
    reason: string | undefined,
  ): Promise<DecideResult> {
    if (this.repository === null) return { kind: "not_found" };

    const now = this.now();
    const current = await this.repository.findById(id);
    if (current === null) return { kind: "not_found" };

    if (current.status === "PENDING" && current.expiresAt <= now) {
      await this.expireOne(current, now);
      return { kind: "expired", approval: (await this.repository.findById(id)) ?? current };
    }
    if (current.status !== "PENDING") {
      return {
        kind: current.status === "EXPIRED" ? "expired" : "already_decided",
        approval: current,
      };
    }

    const decisionReason = reason ?? null;
    const updated = await this.repository.decide(id, status, approverId, now, decisionReason);
    if (updated === null) {
      // Lost a race (another admin decided, or it expired between reads).
      const after = await this.repository.findById(id);
      if (after === null) return { kind: "not_found" };
      return { kind: after.status === "EXPIRED" ? "expired" : "already_decided", approval: after };
    }

    this.auditSink.record(
      buildApprovalAuditEvent(
        status === "APPROVED" ? "approval_approved" : "approval_denied",
        updated,
      ),
    );
    return { kind: status === "APPROVED" ? "approved" : "denied", approval: updated };
  }

  /**
   * Atomically consume an APPROVED approval for the request that presents it.
   * Any mismatch — wrong request, wrong agent/server, expired, still pending,
   * already consumed — refuses execution.
   */
  async consume(id: string, context: SecurityContext, consumedBy: string): Promise<ConsumeResult> {
    if (this.repository === null) return { kind: "not_found" };

    const now = this.now();
    const current = await this.repository.findById(id);
    if (current === null) return { kind: "not_found" };

    // Expiry is checked before anything else so an expired approval can never
    // be executed even if its status somehow reads APPROVED.
    if (current.expiresAt <= now) {
      if (current.status === "PENDING") await this.expireOne(current, now);
      return { kind: "expired", approval: (await this.repository.findById(id)) ?? current };
    }
    if (current.status === "EXPIRED") return { kind: "expired", approval: current };
    if (current.status === "PENDING") return { kind: "not_approved", approval: current };
    if (current.status === "DENIED") return { kind: "not_approved", approval: current };
    if (current.consumedAt !== null) return { kind: "already_consumed", approval: current };

    // An approval grants authority only for the EXACT request it was created for.
    const binding = bindingOf(context);
    if (!sameBinding(current, binding)) return { kind: "binding_mismatch", approval: current };

    const consumed = await this.repository.consume(id, now, consumedBy);
    if (consumed === null) {
      const after = await this.repository.findById(id);
      if (after === null) return { kind: "not_found" };
      return { kind: "already_consumed", approval: after };
    }
    return { kind: "ok", approval: consumed };
  }

  /**
   * Mark every pending approval past its expiry as EXPIRED, auditing each.
   * Idempotent; safe to call from list/read paths and a periodic sweeper.
   */
  async expireStale(): Promise<readonly ApprovalRecord[]> {
    if (this.repository === null) return [];
    const now = this.now();
    const expired = await this.repository.expireStale(now);
    for (const record of expired) {
      this.auditSink.record(buildApprovalAuditEvent("approval_expired", record));
    }
    return expired;
  }

  private async expireOne(record: ApprovalRecord, now: number): Promise<void> {
    if (this.repository === null) return;
    const changed = await this.repository.markExpired(record.id, now);
    if (changed) {
      this.auditSink.record(
        buildApprovalAuditEvent("approval_expired", {
          ...record,
          status: "EXPIRED",
          decidedAt: now,
        }),
      );
    }
  }
}
