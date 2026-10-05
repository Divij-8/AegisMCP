import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "@aegis/gateway/db";
import { buildPgRepositories } from "@aegis/gateway/repositories/pg";

const DATABASE_URL = process.env.DATABASE_URL;
const hasDb = typeof DATABASE_URL === "string" && DATABASE_URL.length > 0;

const identity = {
  agent: { id: "int-agent", name: "int-agent" },
  server: {
    id: "int-server",
    name: "int-server",
    upstreamUrl: "http://127.0.0.1:1/mcp",
  },
};

const d = describe.skipIf(!hasDb);

d("persistence + audit foundation (PostgreSQL)", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: DATABASE_URL });
    await runMigrations(pool);
  });

  afterAll(async () => {
    // Remove this suite's rows so a later suite never sees leftover enabled
    // policies (the gateway loads every enabled policy from the database).
    await pool.query("DELETE FROM audit_events WHERE agent_id = 'int-agent'");
    await pool.query("DELETE FROM policies WHERE id LIKE 'repo-%'");
    await pool.query("DELETE FROM agents WHERE id LIKE 'int-%'");
    await pool.query("DELETE FROM mcp_servers WHERE id LIKE 'int-%'");
    await pool.end();
  });

  async function rows(sql: string): Promise<Record<string, unknown>[]> {
    const result = await pool.query(sql);
    return result.rows as Record<string, unknown>[];
  }

  it("migrations are idempotent", async () => {
    await expect(runMigrations(pool)).resolves.toMatchObject({ applied: [] });
  });

  it("agent and server upserts are idempotent", async () => {
    const repos = buildPgRepositories(pool);
    await repos.agents.upsert(identity.agent);
    await repos.agents.upsert(identity.agent);
    await repos.servers.upsert(identity.server);
    await repos.servers.upsert(identity.server);
    await expect(repos.agents.exists(identity.agent.id)).resolves.toBe(true);
    await expect(repos.servers.exists(identity.server.id)).resolves.toBe(true);
    const agentRows = await rows(`SELECT * FROM agents WHERE id = 'int-agent'`);
    expect(agentRows).toHaveLength(1);
  });

  it("policy upsert and setEnabled drive listEnabled", async () => {
    const repos = buildPgRepositories(pool);
    await pool.query("DELETE FROM policies WHERE id LIKE 'repo-%'");
    await repos.policies.upsert({
      id: "repo-allow-echo",
      decision: "ALLOW",
      match: { tool: "echo" },
      reason: "safe",
    });
    await repos.policies.upsert({
      id: "repo-deny-delete",
      decision: "DENY",
      match: { tool: "database.delete" },
      reason: "dangerous",
    });

    let enabled = await repos.policies.listEnabled();
    expect(enabled.map((p) => p.id).filter((id) => id.startsWith("repo-"))).toEqual([
      "repo-allow-echo",
      "repo-deny-delete",
    ]);

    await repos.policies.setEnabled("repo-allow-echo", false);
    enabled = await repos.policies.listEnabled();
    expect(enabled.map((p) => p.id)).not.toContain("repo-allow-echo");

    await repos.policies.setEnabled("repo-allow-echo", true);
    enabled = await repos.policies.listEnabled();
    expect(enabled.map((p) => p.id)).toContain("repo-allow-echo");
  });

  it("audit batch inserts require agents/servers (FK) and round-trip", async () => {
    const repos = buildPgRepositories(pool);
    await pool.query("DELETE FROM audit_events WHERE agent_id = 'int-agent'");
    await repos.agents.upsert(identity.agent);
    await repos.servers.upsert(identity.server);

    const base = {
      eventType: "request" as const,
      occurredAt: Date.now(),
      agentId: identity.agent.id,
      serverId: identity.server.id,
      method: "tools/call",
      toolName: "echo",
      decision: "ALLOW" as const,
      policyId: "allow-echo",
      reason: "safe",
      outcome: "forwarded" as const,
      upstreamStatus: 200,
      latencyMs: 4,
    };
    await repos.auditEvents.insertBatch([
      base,
      {
        ...base,
        eventType: "notification",
        requestId: null,
        toolName: undefined,
        decision: null,
        policyId: null,
      },
    ]);

    const auditRows = await rows(
      "SELECT * FROM audit_events WHERE agent_id = 'int-agent' ORDER BY id",
    );
    expect(auditRows).toHaveLength(2);
    expect(auditRows[0]!["event_type"]).toBe("request");
    expect(auditRows[1]!["event_type"]).toBe("notification");
    expect(auditRows[1]!["request_id"]).toBeNull();
    expect(auditRows[0]!["tool_args_hash"]).toBeNull();
    // No raw tool arguments column exists at all.
    expect(auditRows[0]).not.toHaveProperty("tool_arguments");
  });
});
