/**
 * In-memory repository implementations.
 *
 * Reference behavior for the pg implementations — used by unit tests and
 * available for a future pure in-memory persistence mode. Not wired into
 * the app today: no DATABASE_URL means persistence is disabled entirely,
 * preserving the pre-Phase-4 behavior exactly.
 */

import type { AgentIdentity, ServerIdentity } from "../security/identity.js";
import type { Policy } from "../policy/types.js";
import type { AuditEvent } from "../audit/types.js";
import type {
  AgentCredentialRecord,
  AgentRepository,
  ApprovalRepository,
  AuditEventRepository,
  AuditListFilter,
  CredentialRepository,
  NewAgentCredential,
  Page,
  PageQuery,
  PolicyRepository,
  Repositories,
  ServerRepository,
} from "./types.js";
import type {
  ApprovalBinding,
  ApprovalListFilter,
  ApprovalRecord,
  NewApproval,
} from "../approvals/types.js";

function clonePolicy(policy: Policy): Policy {
  return Object.freeze({ ...policy, match: { ...policy.match } });
}

function paginate<T>(items: readonly T[], page: PageQuery): Page<T> {
  return {
    items: items.slice(page.offset, page.offset + page.limit),
    total: items.length,
    limit: page.limit,
    offset: page.offset,
  };
}

function byId(a: { id: string }, b: { id: string }): number {
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

export class InMemoryAgentRepository implements AgentRepository {
  private readonly agents = new Map<string, AgentIdentity>();

  async upsert(agent: AgentIdentity): Promise<void> {
    const existing = this.agents.get(agent.id);
    // Mirror pg: an explicit role wins; otherwise keep the existing role.
    const role = agent.role ?? existing?.role;
    this.agents.set(agent.id, { ...agent, ...(role !== undefined ? { role } : {}) });
  }

  async exists(id: string): Promise<boolean> {
    return this.agents.has(id);
  }

  async findById(id: string): Promise<AgentIdentity | null> {
    const agent = this.agents.get(id);
    return agent === undefined ? null : { ...agent };
  }

  async list(page: PageQuery): Promise<Page<AgentIdentity>> {
    return paginate([...this.agents.values()].sort(byId), page);
  }

  async setRole(id: string, role: string): Promise<boolean> {
    const existing = this.agents.get(id);
    if (existing === undefined) return false;
    this.agents.set(id, { ...existing, role: role as AgentIdentity["role"] });
    return true;
  }
}

export class InMemoryServerRepository implements ServerRepository {
  private readonly servers = new Map<string, ServerIdentity>();

  async upsert(server: ServerIdentity): Promise<void> {
    this.servers.set(server.id, { ...server });
  }

  async exists(id: string): Promise<boolean> {
    return this.servers.has(id);
  }

  async findById(id: string): Promise<ServerIdentity | null> {
    const server = this.servers.get(id);
    return server === undefined ? null : { ...server };
  }

  async list(page: PageQuery): Promise<Page<ServerIdentity>> {
    return paginate([...this.servers.values()].sort(byId), page);
  }
}

export class InMemoryPolicyRepository implements PolicyRepository {
  private readonly policies = new Map<string, { policy: Policy; enabled: boolean }>();

  async listEnabled(): Promise<readonly Policy[]> {
    return [...this.policies.values()]
      .filter((entry) => entry.enabled)
      .map((entry) => clonePolicy(entry.policy))
      .sort(byId);
  }

  async listAll(page: PageQuery): Promise<Page<Policy>> {
    const items = [...this.policies.values()]
      .map((entry) => ({
        ...clonePolicy(entry.policy),
        ...(entry.enabled ? {} : { enabled: false }),
      }))
      .sort(byId);
    return paginate(items, page);
  }

  async findById(id: string): Promise<Policy | null> {
    const entry = this.policies.get(id);
    if (entry === undefined) return null;
    return {
      ...clonePolicy(entry.policy),
      ...(entry.enabled ? {} : { enabled: false }),
    };
  }

  async upsert(policy: Policy & { readonly enabled?: boolean }): Promise<void> {
    const { enabled, ...rest } = policy;
    this.policies.set(policy.id, {
      policy: clonePolicy(rest as Policy),
      enabled: enabled ?? true,
    });
  }

  async setEnabled(id: string, enabled: boolean): Promise<void> {
    const existing = this.policies.get(id);
    if (!existing) throw new Error(`Policy "${id}" not found`);
    this.policies.set(id, { ...existing, enabled });
  }

  async remove(id: string): Promise<boolean> {
    return this.policies.delete(id);
  }
}

export class InMemoryAuditEventRepository implements AuditEventRepository {
  readonly events: AuditEvent[] = [];

  async insertBatch(events: readonly AuditEvent[]): Promise<void> {
    this.events.push(...events.map((event) => ({ ...event })));
  }

  async list(filter: AuditListFilter, page: PageQuery): Promise<Page<AuditEvent & { id: string }>> {
    const withIds = this.events.map((event, index) => ({ id: String(index + 1), ...event }));
    const matches = withIds.filter((event) => {
      if (filter.eventType !== undefined && event.eventType !== filter.eventType) return false;
      if (filter.agentId !== undefined && event.agentId !== filter.agentId) return false;
      if (filter.serverId !== undefined && event.serverId !== filter.serverId) return false;
      if (filter.decision !== undefined && event.decision !== filter.decision) return false;
      if (filter.outcome !== undefined && event.outcome !== filter.outcome) return false;
      if (filter.approvalId !== undefined && event.approvalId !== filter.approvalId) return false;
      if (filter.since !== undefined && event.occurredAt < filter.since) return false;
      if (filter.until !== undefined && event.occurredAt > filter.until) return false;
      return true;
    });
    // Newest first, matching pg's ORDER BY id DESC.
    matches.reverse();
    return paginate(matches, page);
  }

  async findById(id: string): Promise<(AuditEvent & { id: string }) | null> {
    const index = Number(id) - 1;
    const event = this.events[index];
    return event === undefined ? null : { id, ...event };
  }
}

export class InMemoryApprovalRepository implements ApprovalRepository {
  private readonly approvals = new Map<string, ApprovalRecord>();

  private bindingKey(binding: ApprovalBinding): string {
    return [
      binding.agentId,
      binding.serverId,
      binding.method,
      binding.toolName ?? "",
      binding.argsHash,
      binding.argsHashAlgo,
    ].join("\u0000");
  }

  async create(approval: NewApproval): Promise<void> {
    if (this.approvals.has(approval.id)) {
      throw new Error(`Approval "${approval.id}" already exists`);
    }
    this.approvals.set(
      approval.id,
      Object.freeze({
        ...approval,
        arguments: Object.freeze({ ...approval.arguments }),
        decision: "REQUIRE_APPROVAL" as const,
        status: "PENDING" as const,
        approverId: null,
        decidedAt: null,
        decisionReason: null,
        consumedAt: null,
      }),
    );
  }

  async findById(id: string): Promise<ApprovalRecord | null> {
    return this.approvals.get(id) ?? null;
  }

  async findPendingByBinding(binding: ApprovalBinding): Promise<ApprovalRecord | null> {
    const key = this.bindingKey(binding);
    for (const record of this.approvals.values()) {
      if (record.status === "PENDING" && this.bindingKey(record) === key) return record;
    }
    return null;
  }

  async decide(
    id: string,
    status: "APPROVED" | "DENIED",
    approverId: string,
    decidedAt: number,
    decisionReason: string | null,
  ): Promise<ApprovalRecord | null> {
    const record = this.approvals.get(id);
    if (record === undefined || record.status !== "PENDING" || record.expiresAt <= decidedAt) {
      return null;
    }
    const next: ApprovalRecord = Object.freeze({
      ...record,
      status,
      approverId,
      decidedAt,
      decisionReason,
    });
    this.approvals.set(id, next);
    return next;
  }

  async consume(
    id: string,
    consumedAt: number,
    consumedBy: string,
  ): Promise<ApprovalRecord | null> {
    void consumedBy;
    const record = this.approvals.get(id);
    if (
      record === undefined ||
      record.status !== "APPROVED" ||
      record.consumedAt !== null ||
      record.expiresAt <= consumedAt
    ) {
      return null;
    }
    const next: ApprovalRecord = Object.freeze({ ...record, consumedAt });
    this.approvals.set(id, next);
    return next;
  }

  async markExpired(id: string, now: number): Promise<boolean> {
    const record = this.approvals.get(id);
    if (record === undefined || record.status !== "PENDING") return false;
    this.approvals.set(id, Object.freeze({ ...record, status: "EXPIRED", decidedAt: now }));
    return true;
  }

  async expireStale(now: number): Promise<readonly ApprovalRecord[]> {
    const expired: ApprovalRecord[] = [];
    for (const [id, record] of this.approvals) {
      if (record.status === "PENDING" && record.expiresAt <= now) {
        const next: ApprovalRecord = Object.freeze({
          ...record,
          status: "EXPIRED",
          decidedAt: now,
        });
        this.approvals.set(id, next);
        expired.push(next);
      }
    }
    return expired;
  }

  async list(filter: ApprovalListFilter, page: PageQuery): Promise<Page<ApprovalRecord>> {
    const items = [...this.approvals.values()]
      .filter((record) => {
        if (filter.status !== undefined && record.status !== filter.status) return false;
        if (filter.agentId !== undefined && record.agentId !== filter.agentId) return false;
        if (filter.serverId !== undefined && record.serverId !== filter.serverId) return false;
        return true;
      })
      .sort((a, b) => b.createdAt - a.createdAt || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    return paginate(items, page);
  }
}

interface MemoryCredentialEntry {
  readonly keyId: string;
  readonly agent: AgentIdentity;
  readonly label: string | undefined;
  readonly secretHash: string;
  readonly salt: string;
  readonly hashAlgo: string;
  readonly createdAt: number;
  readonly expiresAt: number | null;
  readonly revokedAt: number | null;
}

function toCredentialRecord(entry: MemoryCredentialEntry): AgentCredentialRecord {
  return Object.freeze({
    keyId: entry.keyId,
    agent: Object.freeze({ ...entry.agent }),
    label: entry.label,
    secretHash: entry.secretHash,
    salt: entry.salt,
    hashAlgo: entry.hashAlgo,
    createdAt: entry.createdAt,
    expiresAt: entry.expiresAt,
    revokedAt: entry.revokedAt,
  });
}

export class InMemoryCredentialRepository implements CredentialRepository {
  private readonly credentials = new Map<string, MemoryCredentialEntry>();

  async findByKeyId(keyId: string): Promise<AgentCredentialRecord | null> {
    const entry = this.credentials.get(keyId);
    return entry === undefined ? null : toCredentialRecord(entry);
  }

  async create(credential: NewAgentCredential): Promise<void> {
    if (this.credentials.has(credential.keyId)) {
      throw new Error(`Credential "${credential.keyId}" already exists`);
    }
    this.credentials.set(credential.keyId, {
      keyId: credential.keyId,
      agent: { ...credential.agent },
      label: credential.label,
      secretHash: credential.secretHash,
      salt: credential.salt,
      hashAlgo: credential.hashAlgo,
      createdAt: credential.createdAt,
      expiresAt: credential.expiresAt,
      revokedAt: null,
    });
  }

  async revoke(keyId: string, revokedAt: number): Promise<boolean> {
    const entry = this.credentials.get(keyId);
    if (entry === undefined || entry.revokedAt !== null) return false;
    this.credentials.set(keyId, { ...entry, revokedAt });
    return true;
  }

  async revokeAll(agentId: string, revokedAt: number): Promise<number> {
    let count = 0;
    for (const [keyId, entry] of this.credentials) {
      if (entry.agent.id === agentId && entry.revokedAt === null) {
        this.credentials.set(keyId, { ...entry, revokedAt });
        count += 1;
      }
    }
    return count;
  }

  async listByAgent(agentId: string): Promise<readonly AgentCredentialRecord[]> {
    return [...this.credentials.values()]
      .filter((entry) => entry.agent.id === agentId)
      .sort(
        (a, b) => a.createdAt - b.createdAt || (a.keyId < b.keyId ? -1 : a.keyId > b.keyId ? 1 : 0),
      )
      .map(toCredentialRecord);
  }
}

export function buildInMemoryRepositories(): Repositories {
  return {
    agents: new InMemoryAgentRepository(),
    servers: new InMemoryServerRepository(),
    policies: new InMemoryPolicyRepository(),
    auditEvents: new InMemoryAuditEventRepository(),
    credentials: new InMemoryCredentialRepository(),
    approvals: new InMemoryApprovalRepository(),
  };
}
