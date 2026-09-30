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
  AuditEventRepository,
  CredentialRepository,
  NewAgentCredential,
  PolicyRepository,
  Repositories,
  ServerRepository,
} from "./types.js";

function clonePolicy(policy: Policy): Policy {
  return Object.freeze({ ...policy, match: { ...policy.match } });
}

export class InMemoryAgentRepository implements AgentRepository {
  private readonly agents = new Map<string, AgentIdentity>();

  async upsert(agent: AgentIdentity): Promise<void> {
    this.agents.set(agent.id, { ...agent });
  }

  async exists(id: string): Promise<boolean> {
    return this.agents.has(id);
  }

  async findById(id: string): Promise<AgentIdentity | null> {
    const agent = this.agents.get(id);
    return agent === undefined ? null : { ...agent };
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
}

export class InMemoryPolicyRepository implements PolicyRepository {
  private readonly policies = new Map<string, { policy: Policy; enabled: boolean }>();

  async listEnabled(): Promise<readonly Policy[]> {
    return [...this.policies.values()]
      .filter((entry) => entry.enabled)
      .map((entry) => clonePolicy(entry.policy))
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
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
}

export class InMemoryAuditEventRepository implements AuditEventRepository {
  readonly events: AuditEvent[] = [];

  async insertBatch(events: readonly AuditEvent[]): Promise<void> {
    this.events.push(...events.map((event) => ({ ...event })));
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
  };
}
