/**
 * Repository interfaces — the boundary between the domain layer and SQL.
 *
 * Implementations live in pg-*.ts (real) and memory.ts (tests / no-DB
 * reference). Domain types (Policy, AuditEvent, identity types) are plain
 * data and are never coupled to pg.
 */

import type { AgentIdentity, ServerIdentity } from "../security/identity.js";
import type { Policy } from "../policy/types.js";
import type { AuditEvent } from "../audit/types.js";
import type {
  ApprovalBinding,
  ApprovalListFilter,
  ApprovalRecord,
  ApprovalStatus,
  NewApproval,
} from "../approvals/types.js";

/** Standard pagination window shared by every control-plane list endpoint. */
export interface PageQuery {
  readonly limit: number;
  readonly offset: number;
}

export interface Page<T> {
  readonly items: readonly T[];
  readonly total: number;
  readonly limit: number;
  readonly offset: number;
}

export interface AgentRepository {
  upsert(agent: AgentIdentity): Promise<void>;
  exists(id: string): Promise<boolean>;
  /** Canonical agent from the registry, or null when it does not exist. */
  findById(id: string): Promise<AgentIdentity | null>;
  /** Paginated registry listing, ordered by id. */
  list(page: PageQuery): Promise<Page<AgentIdentity>>;
  /** Set the authorization role for an agent. Returns false when unknown. */
  setRole(id: string, role: string): Promise<boolean>;
}

export interface ServerRepository {
  upsert(server: ServerIdentity): Promise<void>;
  exists(id: string): Promise<boolean>;
  findById(id: string): Promise<ServerIdentity | null>;
  list(page: PageQuery): Promise<Page<ServerIdentity>>;
}

export interface PolicyRepository {
  /** All enabled policies, ordered deterministically (by id). */
  listEnabled(): Promise<readonly Policy[]>;
  /** All policies including disabled, ordered by id. */
  listAll(page: PageQuery): Promise<Page<Policy>>;
  findById(id: string): Promise<Policy | null>;
  upsert(policy: Policy & { readonly enabled?: boolean }): Promise<void>;
  setEnabled(id: string, enabled: boolean): Promise<void>;
  /** Hard-delete a policy. Returns false when it did not exist. */
  remove(id: string): Promise<boolean>;
}

export interface AuditListFilter {
  readonly eventType?: string;
  readonly agentId?: string;
  readonly serverId?: string;
  readonly decision?: string;
  readonly outcome?: string;
  readonly approvalId?: string;
  readonly since?: number;
  readonly until?: number;
}

export interface AuditEventRepository {
  /** Insert a batch in a single transaction. */
  insertBatch(events: readonly AuditEvent[]): Promise<void>;
  list(filter: AuditListFilter, page: PageQuery): Promise<Page<AuditEvent & { id: string }>>;
  findById(id: string): Promise<(AuditEvent & { id: string }) | null>;
}

export interface ApprovalRepository {
  create(approval: NewApproval): Promise<void>;
  findById(id: string): Promise<ApprovalRecord | null>;
  /** The single PENDING approval for an exact binding, if one exists. */
  findPendingByBinding(binding: ApprovalBinding): Promise<ApprovalRecord | null>;
  /**
   * Transition PENDING → APPROVED/DENIED, but only when still pending and not
   * yet expired. Returns the updated record, or null when the guard failed.
   */
  decide(
    id: string,
    status: Extract<ApprovalStatus, "APPROVED" | "DENIED">,
    approverId: string,
    decidedAt: number,
    decisionReason: string | null,
  ): Promise<ApprovalRecord | null>;
  /**
   * Single-use execution: APPROVED → consumed, only when not expired and not
   * already consumed. Returns the updated record, or null when the guard failed.
   */
  consume(id: string, consumedAt: number, consumedBy: string): Promise<ApprovalRecord | null>;
  /** Mark a specific pending approval EXPIRED. Returns true when it changed. */
  markExpired(id: string, now: number): Promise<boolean>;
  /** Mark every pending approval past its expiry EXPIRED; return the affected. */
  expireStale(now: number): Promise<readonly ApprovalRecord[]>;
  list(filter: ApprovalListFilter, page: PageQuery): Promise<Page<ApprovalRecord>>;
}

/**
 * Stored agent credential. Contains ONLY the hashed secret — plaintext API
 * keys never exist in this shape or in the database.
 */
export interface AgentCredentialRecord {
  /** Public lookup identifier parsed from the presented key. */
  readonly keyId: string;
  /** Owning agent, resolved from the agents registry. */
  readonly agent: AgentIdentity;
  readonly label: string | undefined;
  readonly secretHash: string;
  readonly salt: string;
  readonly hashAlgo: string;
  /** Epoch millis. */
  readonly createdAt: number;
  /** Epoch millis, or null when the credential never expires. */
  readonly expiresAt: number | null;
  /** Epoch millis, or null while the credential is active. */
  readonly revokedAt: number | null;
}

/** Input for creating a credential. Carries the hash, never the secret. */
export interface NewAgentCredential {
  readonly keyId: string;
  readonly agent: AgentIdentity;
  readonly label?: string;
  readonly secretHash: string;
  readonly salt: string;
  readonly hashAlgo: string;
  readonly createdAt: number;
  readonly expiresAt: number | null;
}

export interface CredentialRepository {
  /**
   * Look up a credential by its public key id, joined with its agent.
   *
   * Returns the row REGARDLESS of revoked/expired state so the authenticator
   * can distinguish revoked/expired from a genuinely unknown credential.
   * Returns null when no row matches.
   */
  findByKeyId(keyId: string): Promise<AgentCredentialRecord | null>;
  /** Insert a new credential. Throws on duplicate key_id. */
  create(credential: NewAgentCredential): Promise<void>;
  /** Soft-revoke an active credential. Returns true when a row was revoked. */
  revoke(keyId: string, revokedAt: number): Promise<boolean>;
  /** Soft-revoke every active credential for an agent. Returns how many changed. */
  revokeAll(agentId: string, revokedAt: number): Promise<number>;
  /** All credentials for an agent, ordered by creation time. */
  listByAgent(agentId: string): Promise<readonly AgentCredentialRecord[]>;
}

export interface Repositories {
  readonly agents: AgentRepository;
  readonly servers: ServerRepository;
  readonly policies: PolicyRepository;
  readonly auditEvents: AuditEventRepository;
  readonly credentials: CredentialRepository;
  readonly approvals: ApprovalRepository;
}
