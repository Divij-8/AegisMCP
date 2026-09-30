/**
 * PostgreSQL repository implementations.
 *
 * These are the ONLY files in the codebase that know SQL for domain data.
 * Every method maps rows through ../repositories/mappers.ts before anything
 * sees a database shape.
 */

import type { Pool } from "pg";
import type { AgentIdentity, ServerIdentity } from "../security/identity.js";
import type { Policy } from "../policy/types.js";
import type { AuditEvent } from "../audit/types.js";
import type {
  AgentCredentialRecord,
  AgentRepository,
  CredentialRepository,
  NewAgentCredential,
  PolicyRepository,
  Repositories,
  ServerRepository,
  AuditEventRepository,
} from "./types.js";
import { toDomainAgent, toDomainAgentCredential, toDomainPolicy } from "./mappers.js";

const DECISIONS: readonly string[] = ["ALLOW", "DENY", "REQUIRE_APPROVAL"];

export class PgAgentRepository implements AgentRepository {
  constructor(private readonly pool: Pool) {}

  async upsert(agent: AgentIdentity): Promise<void> {
    await this.pool.query(
      `INSERT INTO agents (id, name) VALUES ($1, $2)
       ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, updated_at = now()`,
      [agent.id, agent.name],
    );
  }

  async exists(id: string): Promise<boolean> {
    const { rows } = await this.pool.query("SELECT 1 FROM agents WHERE id = $1", [id]);
    return rows.length > 0;
  }

  async findById(id: string): Promise<AgentIdentity | null> {
    const { rows } = await this.pool.query("SELECT id, name FROM agents WHERE id = $1", [id]);
    const row = rows[0] as Record<string, unknown> | undefined;
    return row === undefined ? null : toDomainAgent(row);
  }
}

export class PgServerRepository implements ServerRepository {
  constructor(private readonly pool: Pool) {}

  async upsert(server: ServerIdentity): Promise<void> {
    await this.pool.query(
      `INSERT INTO mcp_servers (id, name, upstream_url) VALUES ($1, $2, $3)
       ON CONFLICT (id) DO UPDATE
         SET name = EXCLUDED.name, upstream_url = EXCLUDED.upstream_url, updated_at = now()`,
      [server.id, server.name, server.upstreamUrl],
    );
  }

  async exists(id: string): Promise<boolean> {
    const { rows } = await this.pool.query("SELECT 1 FROM mcp_servers WHERE id = $1", [id]);
    return rows.length > 0;
  }
}

export class PgPolicyRepository implements PolicyRepository {
  constructor(private readonly pool: Pool) {}

  async listEnabled(): Promise<readonly Policy[]> {
    const { rows } = await this.pool.query(
      "SELECT id, decision, match, reason, priority, enabled FROM policies WHERE enabled ORDER BY id",
    );
    return rows.map((row) => toDomainPolicy(row as Record<string, unknown>));
  }

  async upsert(policy: Policy & { readonly enabled?: boolean }): Promise<void> {
    if (!DECISIONS.includes(policy.decision)) {
      throw new Error(`Invalid decision "${policy.decision}" for policy "${policy.id}"`);
    }
    await this.pool.query(
      `INSERT INTO policies (id, decision, match, reason, priority, enabled)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (id) DO UPDATE SET
         decision = EXCLUDED.decision,
         match = EXCLUDED.match,
         reason = EXCLUDED.reason,
         priority = EXCLUDED.priority,
         enabled = EXCLUDED.enabled,
         updated_at = now()`,
      [
        policy.id,
        policy.decision,
        JSON.stringify(policy.match),
        policy.reason,
        policy.priority ?? 0,
        policy.enabled ?? true,
      ],
    );
  }

  async setEnabled(id: string, enabled: boolean): Promise<void> {
    const { rowCount } = await this.pool.query(
      "UPDATE policies SET enabled = $2, updated_at = now() WHERE id = $1",
      [id, enabled],
    );
    if (rowCount === 0) {
      throw new Error(`Policy "${id}" not found`);
    }
  }
}

const CREDENTIAL_COLUMNS = `
  c.key_id, c.agent_id, c.label, c.secret_hash, c.salt, c.hash_algo,
  c.created_at, c.expires_at, c.revoked_at,
  a.name AS agent_name
`;

export class PgCredentialRepository implements CredentialRepository {
  constructor(private readonly pool: Pool) {}

  async findByKeyId(keyId: string): Promise<AgentCredentialRecord | null> {
    const { rows } = await this.pool.query(
      `SELECT ${CREDENTIAL_COLUMNS}
       FROM agent_credentials c
       JOIN agents a ON a.id = c.agent_id
       WHERE c.key_id = $1`,
      [keyId],
    );
    const row = rows[0] as Record<string, unknown> | undefined;
    return row === undefined ? null : toDomainAgentCredential(row);
  }

  async create(credential: NewAgentCredential): Promise<void> {
    await this.pool.query(
      `INSERT INTO agent_credentials (
         key_id, agent_id, label, secret_hash, salt, hash_algo, created_at, expires_at
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        credential.keyId,
        credential.agent.id,
        credential.label ?? null,
        credential.secretHash,
        credential.salt,
        credential.hashAlgo,
        new Date(credential.createdAt),
        credential.expiresAt === null ? null : new Date(credential.expiresAt),
      ],
    );
  }

  async revoke(keyId: string, revokedAt: number): Promise<boolean> {
    const { rowCount } = await this.pool.query(
      "UPDATE agent_credentials SET revoked_at = $2 WHERE key_id = $1 AND revoked_at IS NULL",
      [keyId, new Date(revokedAt)],
    );
    return (rowCount ?? 0) > 0;
  }

  async listByAgent(agentId: string): Promise<readonly AgentCredentialRecord[]> {
    const { rows } = await this.pool.query(
      `SELECT ${CREDENTIAL_COLUMNS}
       FROM agent_credentials c
       JOIN agents a ON a.id = c.agent_id
       WHERE c.agent_id = $1
       ORDER BY c.created_at, c.key_id`,
      [agentId],
    );
    return rows.map((row) => toDomainAgentCredential(row as Record<string, unknown>));
  }
}

export class PgAuditEventRepository implements AuditEventRepository {
  constructor(private readonly pool: Pool) {}

  async insertBatch(events: readonly AuditEvent[]): Promise<void> {
    if (events.length === 0) return;

    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      for (const event of events) {
        await client.query(
          `INSERT INTO audit_events (
             event_type, request_id, occurred_at, agent_id, server_id,
             method, tool_name, decision, policy_id, reason,
             outcome, upstream_status, latency_ms, tool_args_hash, tool_args_hash_algo,
             key_id, auth_failure_reason
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
          [
            event.eventType,
            event.requestId === null ? null : String(event.requestId),
            new Date(event.occurredAt),
            event.agentId,
            event.serverId,
            event.method,
            event.toolName ?? null,
            event.decision ?? null,
            event.policyId ?? null,
            event.reason,
            event.outcome,
            event.upstreamStatus ?? null,
            event.latencyMs,
            event.toolArgumentsRedaction?.hash ?? null,
            event.toolArgumentsRedaction?.algorithm ?? null,
            event.keyId ?? null,
            event.authFailureReason ?? null,
          ],
        );
      }
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  }
}

export function buildPgRepositories(pool: Pool): Repositories {
  return {
    agents: new PgAgentRepository(pool),
    servers: new PgServerRepository(pool),
    policies: new PgPolicyRepository(pool),
    auditEvents: new PgAuditEventRepository(pool),
    credentials: new PgCredentialRepository(pool),
  };
}
