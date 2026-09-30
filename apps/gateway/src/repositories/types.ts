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

export interface AgentRepository {
  upsert(agent: AgentIdentity): Promise<void>;
  exists(id: string): Promise<boolean>;
  /** Canonical agent from the registry, or null when it does not exist. */
  findById(id: string): Promise<AgentIdentity | null>;
}

export interface ServerRepository {
  upsert(server: ServerIdentity): Promise<void>;
  exists(id: string): Promise<boolean>;
}

export interface PolicyRepository {
  /** All enabled policies, ordered deterministically (by id). */
  listEnabled(): Promise<readonly Policy[]>;
  upsert(policy: Policy & { readonly enabled?: boolean }): Promise<void>;
  setEnabled(id: string, enabled: boolean): Promise<void>;
}

export interface AuditEventRepository {
  /** Insert a batch in a single transaction. */
  insertBatch(events: readonly AuditEvent[]): Promise<void>;
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
  /** All credentials for an agent, ordered by creation time. */
  listByAgent(agentId: string): Promise<readonly AgentCredentialRecord[]>;
}

export interface Repositories {
  readonly agents: AgentRepository;
  readonly servers: ServerRepository;
  readonly policies: PolicyRepository;
  readonly auditEvents: AuditEventRepository;
  readonly credentials: CredentialRepository;
}
