/**
 * PostgreSQL repository implementations.
 *
 * These are the ONLY files in the codebase that know SQL for domain data.
 * Every method maps rows through ../repositories/mappers.ts before anything
 * sees a database shape.
 */

import type { Pool } from "pg";
import type { AgentIdentity, ServerIdentity } from "../security/identity.js";
import { resolveRole } from "../security/rbac.js";
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
import {
  toDomainAgent,
  toDomainAgentCredential,
  toDomainApproval,
  toDomainAuditEvent,
  toDomainPolicy,
} from "./mappers.js";

const DECISIONS: readonly string[] = ["ALLOW", "DENY", "REQUIRE_APPROVAL"];

/** Build a SQL LIMIT/OFFSET pair, clamped by the repository contract. */
function window(page: PageQuery): [number, number] {
  return [page.limit, page.offset];
}

export class PgAgentRepository implements AgentRepository {
  constructor(private readonly pool: Pool) {}

  async upsert(agent: AgentIdentity): Promise<void> {
    // Role is only overwritten when explicitly provided so an existing
    // administrator is not silently demoted by a routine identity upsert.
    await this.pool.query(
      `INSERT INTO agents (id, name, role) VALUES ($1, $2, $3)
       ON CONFLICT (id) DO UPDATE SET
         name = EXCLUDED.name,
         role = CASE WHEN $4 THEN EXCLUDED.role ELSE agents.role END,
         updated_at = now()`,
      [agent.id, agent.name, resolveRole(agent), agent.role !== undefined],
    );
  }

  async exists(id: string): Promise<boolean> {
    const { rows } = await this.pool.query("SELECT 1 FROM agents WHERE id = $1", [id]);
    return rows.length > 0;
  }

  async findById(id: string): Promise<AgentIdentity | null> {
    const { rows } = await this.pool.query("SELECT id, name, role FROM agents WHERE id = $1", [id]);
    const row = rows[0] as Record<string, unknown> | undefined;
    return row === undefined ? null : toDomainAgent(row);
  }

  async list(page: PageQuery): Promise<Page<AgentIdentity>> {
    const [limit, offset] = window(page);
    const { rows } = await this.pool.query(
      "SELECT id, name, role FROM agents ORDER BY id LIMIT $1 OFFSET $2",
      [limit, offset],
    );
    const count = await this.pool.query<{ total: string }>(
      "SELECT COUNT(*)::text AS total FROM agents",
    );
    return {
      items: rows.map((row) => toDomainAgent(row as Record<string, unknown>)),
      total: Number(count.rows[0]?.total ?? 0),
      limit,
      offset,
    };
  }

  async setRole(id: string, role: string): Promise<boolean> {
    const { rowCount } = await this.pool.query(
      "UPDATE agents SET role = $2, updated_at = now() WHERE id = $1",
      [id, role],
    );
    return (rowCount ?? 0) > 0;
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

  async findById(id: string): Promise<ServerIdentity | null> {
    const { rows } = await this.pool.query(
      "SELECT id, name, upstream_url FROM mcp_servers WHERE id = $1",
      [id],
    );
    const row = rows[0] as Record<string, unknown> | undefined;
    return row === undefined
      ? null
      : Object.freeze({
          id: String(row["id"]),
          name: String(row["name"]),
          upstreamUrl: String(row["upstream_url"]),
        });
  }

  async list(page: PageQuery): Promise<Page<ServerIdentity>> {
    const [limit, offset] = window(page);
    const { rows } = await this.pool.query(
      "SELECT id, name, upstream_url FROM mcp_servers ORDER BY id LIMIT $1 OFFSET $2",
      [limit, offset],
    );
    const count = await this.pool.query<{ total: string }>(
      "SELECT COUNT(*)::text AS total FROM mcp_servers",
    );
    return {
      items: rows.map((row) => {
        const r = row as Record<string, unknown>;
        return Object.freeze({
          id: String(r["id"]),
          name: String(r["name"]),
          upstreamUrl: String(r["upstream_url"]),
        });
      }),
      total: Number(count.rows[0]?.total ?? 0),
      limit,
      offset,
    };
  }
}

const POLICY_COLUMNS = "id, decision, match, reason, priority, enabled";

export class PgPolicyRepository implements PolicyRepository {
  constructor(private readonly pool: Pool) {}

  async listEnabled(): Promise<readonly Policy[]> {
    const { rows } = await this.pool.query(
      `SELECT ${POLICY_COLUMNS} FROM policies WHERE enabled ORDER BY id`,
    );
    return rows.map((row) => toDomainPolicy(row as Record<string, unknown>));
  }

  async listAll(page: PageQuery): Promise<Page<Policy>> {
    const [limit, offset] = window(page);
    const { rows } = await this.pool.query(
      `SELECT ${POLICY_COLUMNS} FROM policies ORDER BY id LIMIT $1 OFFSET $2`,
      [limit, offset],
    );
    const count = await this.pool.query<{ total: string }>(
      "SELECT COUNT(*)::text AS total FROM policies",
    );
    return {
      items: rows.map((row) => toDomainPolicy(row as Record<string, unknown>)),
      total: Number(count.rows[0]?.total ?? 0),
      limit,
      offset,
    };
  }

  async findById(id: string): Promise<Policy | null> {
    const { rows } = await this.pool.query(`SELECT ${POLICY_COLUMNS} FROM policies WHERE id = $1`, [
      id,
    ]);
    const row = rows[0] as Record<string, unknown> | undefined;
    return row === undefined ? null : toDomainPolicy(row);
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

  async remove(id: string): Promise<boolean> {
    const { rowCount } = await this.pool.query("DELETE FROM policies WHERE id = $1", [id]);
    return (rowCount ?? 0) > 0;
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

  async revokeAll(agentId: string, revokedAt: number): Promise<number> {
    const { rowCount } = await this.pool.query(
      "UPDATE agent_credentials SET revoked_at = $2 WHERE agent_id = $1 AND revoked_at IS NULL",
      [agentId, new Date(revokedAt)],
    );
    return rowCount ?? 0;
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

const AUDIT_COLUMNS = `
  id, event_type, request_id, occurred_at, agent_id, server_id, method, tool_name,
  decision, policy_id, reason, outcome, upstream_status, latency_ms,
  tool_args_hash, tool_args_hash_algo, key_id, auth_failure_reason, approval_id, risk_level
`;

/** Build a parameterized audit WHERE clause from a filter. */
function auditWhere(filter: AuditListFilter): { clause: string; values: unknown[] } {
  const conditions: string[] = [];
  const values: unknown[] = [];
  const add = (column: string, value: unknown) => {
    values.push(value);
    conditions.push(`${column} = $${values.length}`);
  };

  if (filter.eventType !== undefined) add("event_type", filter.eventType);
  if (filter.agentId !== undefined) add("agent_id", filter.agentId);
  if (filter.serverId !== undefined) add("server_id", filter.serverId);
  if (filter.decision !== undefined) add("decision", filter.decision);
  if (filter.outcome !== undefined) add("outcome", filter.outcome);
  if (filter.approvalId !== undefined) add("approval_id", filter.approvalId);
  if (filter.since !== undefined) {
    values.push(new Date(filter.since));
    conditions.push(`occurred_at >= $${values.length}`);
  }
  if (filter.until !== undefined) {
    values.push(new Date(filter.until));
    conditions.push(`occurred_at <= $${values.length}`);
  }

  return { clause: conditions.length === 0 ? "" : ` WHERE ${conditions.join(" AND ")}`, values };
}

export class PgAuditEventRepository implements AuditEventRepository {
  constructor(private readonly pool: Pool) {}

  async list(filter: AuditListFilter, page: PageQuery): Promise<Page<AuditEvent & { id: string }>> {
    const { clause, values } = auditWhere(filter);
    const limitIdx = values.length + 1;
    const offsetIdx = values.length + 2;
    const { rows } = await this.pool.query(
      `SELECT ${AUDIT_COLUMNS} FROM audit_events${clause} ORDER BY id DESC LIMIT $${limitIdx} OFFSET $${offsetIdx}`,
      [...values, page.limit, page.offset],
    );
    const count = await this.pool.query<{ total: string }>(
      `SELECT COUNT(*)::text AS total FROM audit_events${clause}`,
      values,
    );
    return {
      items: rows.map((row) => {
        const record = row as Record<string, unknown>;
        return { id: String(record["id"]), ...toDomainAuditEvent(record) };
      }),
      total: Number(count.rows[0]?.total ?? 0),
      limit: page.limit,
      offset: page.offset,
    };
  }

  async findById(id: string): Promise<(AuditEvent & { id: string }) | null> {
    const { rows } = await this.pool.query(
      `SELECT ${AUDIT_COLUMNS} FROM audit_events WHERE id = $1`,
      [id],
    );
    const record = rows[0] as Record<string, unknown> | undefined;
    if (record === undefined) return null;
    return { id: String(record["id"]), ...toDomainAuditEvent(record) };
  }

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
             key_id, auth_failure_reason, approval_id, risk_level
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)`,
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
            event.approvalId ?? null,
            event.riskLevel ?? null,
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

const APPROVAL_COLUMNS = `
  id, request_id, agent_id, server_id, method, tool_name, arguments,
  args_hash, args_hash_algo, policy_id, decision, reason, created_at, expires_at,
  status, approver_id, decided_at, decision_reason, consumed_at
`;

export class PgApprovalRepository implements ApprovalRepository {
  constructor(private readonly pool: Pool) {}

  async create(approval: NewApproval): Promise<void> {
    await this.pool.query(
      `INSERT INTO approvals (
         id, request_id, agent_id, server_id, method, tool_name, arguments,
         args_hash, args_hash_algo, policy_id, decision, reason, created_at, expires_at, status
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'REQUIRE_APPROVAL', $11, $12, $13, 'PENDING')`,
      [
        approval.id,
        approval.requestId === null ? null : String(approval.requestId),
        approval.agentId,
        approval.serverId,
        approval.method,
        approval.toolName ?? null,
        JSON.stringify(approval.arguments),
        approval.argsHash,
        approval.argsHashAlgo,
        approval.policyId,
        approval.reason,
        new Date(approval.createdAt),
        new Date(approval.expiresAt),
      ],
    );
  }

  async findById(id: string): Promise<ApprovalRecord | null> {
    const { rows } = await this.pool.query(
      `SELECT ${APPROVAL_COLUMNS} FROM approvals WHERE id = $1`,
      [id],
    );
    const row = rows[0] as Record<string, unknown> | undefined;
    return row === undefined ? null : toDomainApproval(row);
  }

  async findPendingByBinding(binding: ApprovalBinding): Promise<ApprovalRecord | null> {
    const { rows } = await this.pool.query(
      `SELECT ${APPROVAL_COLUMNS} FROM approvals
       WHERE status = 'PENDING'
         AND agent_id = $1 AND server_id = $2 AND method = $3
         AND COALESCE(tool_name, '') = COALESCE($4, '')
         AND args_hash = $5 AND args_hash_algo = $6
       ORDER BY created_at DESC LIMIT 1`,
      [
        binding.agentId,
        binding.serverId,
        binding.method,
        binding.toolName ?? null,
        binding.argsHash,
        binding.argsHashAlgo,
      ],
    );
    const row = rows[0] as Record<string, unknown> | undefined;
    return row === undefined ? null : toDomainApproval(row);
  }

  async decide(
    id: string,
    status: "APPROVED" | "DENIED",
    approverId: string,
    decidedAt: number,
    decisionReason: string | null,
  ): Promise<ApprovalRecord | null> {
    const { rows } = await this.pool.query(
      `UPDATE approvals
         SET status = $2, approver_id = $3, decided_at = $4, decision_reason = $5
       WHERE id = $1 AND status = 'PENDING' AND expires_at > $4
       RETURNING ${APPROVAL_COLUMNS}`,
      [id, status, approverId, new Date(decidedAt), decisionReason],
    );
    const row = rows[0] as Record<string, unknown> | undefined;
    return row === undefined ? null : toDomainApproval(row);
  }

  async consume(
    id: string,
    consumedAt: number,
    consumedBy: string,
  ): Promise<ApprovalRecord | null> {
    const { rows } = await this.pool.query(
      `UPDATE approvals
         SET consumed_at = $2, consumed_by = $3
       WHERE id = $1 AND status = 'APPROVED' AND consumed_at IS NULL AND expires_at > $2
       RETURNING ${APPROVAL_COLUMNS}`,
      [id, new Date(consumedAt), consumedBy],
    );
    const row = rows[0] as Record<string, unknown> | undefined;
    return row === undefined ? null : toDomainApproval(row);
  }

  async markExpired(id: string, now: number): Promise<boolean> {
    const { rowCount } = await this.pool.query(
      `UPDATE approvals SET status = 'EXPIRED', decided_at = $2
       WHERE id = $1 AND status = 'PENDING'`,
      [id, new Date(now)],
    );
    return (rowCount ?? 0) > 0;
  }

  async expireStale(now: number): Promise<readonly ApprovalRecord[]> {
    const { rows } = await this.pool.query(
      `UPDATE approvals SET status = 'EXPIRED', decided_at = $1
       WHERE status = 'PENDING' AND expires_at <= $1
       RETURNING ${APPROVAL_COLUMNS}`,
      [new Date(now)],
    );
    return rows.map((row) => toDomainApproval(row as Record<string, unknown>));
  }

  async list(filter: ApprovalListFilter, page: PageQuery): Promise<Page<ApprovalRecord>> {
    const conditions: string[] = [];
    const values: unknown[] = [];
    if (filter.status !== undefined) {
      values.push(filter.status);
      conditions.push(`status = $${values.length}`);
    }
    if (filter.agentId !== undefined) {
      values.push(filter.agentId);
      conditions.push(`agent_id = $${values.length}`);
    }
    if (filter.serverId !== undefined) {
      values.push(filter.serverId);
      conditions.push(`server_id = $${values.length}`);
    }
    const clause = conditions.length === 0 ? "" : ` WHERE ${conditions.join(" AND ")}`;

    const { rows } = await this.pool.query(
      `SELECT ${APPROVAL_COLUMNS} FROM approvals${clause}
       ORDER BY created_at DESC, id DESC LIMIT $${values.length + 1} OFFSET $${values.length + 2}`,
      [...values, page.limit, page.offset],
    );
    const count = await this.pool.query<{ total: string }>(
      `SELECT COUNT(*)::text AS total FROM approvals${clause}`,
      values,
    );
    return {
      items: rows.map((row) => toDomainApproval(row as Record<string, unknown>)),
      total: Number(count.rows[0]?.total ?? 0),
      limit: page.limit,
      offset: page.offset,
    };
  }
}

export function buildPgRepositories(pool: Pool): Repositories {
  return {
    agents: new PgAgentRepository(pool),
    servers: new PgServerRepository(pool),
    policies: new PgPolicyRepository(pool),
    auditEvents: new PgAuditEventRepository(pool),
    credentials: new PgCredentialRepository(pool),
    approvals: new PgApprovalRepository(pool),
  };
}
