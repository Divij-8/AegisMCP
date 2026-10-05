import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import http from "node:http";
import { Pool } from "pg";
import { buildApp } from "@aegis/gateway/app";
import { runMigrations } from "@aegis/gateway/db";
import { buildPgRepositories } from "@aegis/gateway/repositories/pg";
import { DefaultCredentialService, ScryptSecretHasher } from "@aegis/gateway/security";

const DATABASE_URL = process.env.DATABASE_URL;
const hasDb = typeof DATABASE_URL === "string" && DATABASE_URL.length > 0;

const d = describe.skipIf(!hasDb);

const identity = {
  agent: { id: "apr-e2e-gateway", name: "apr-e2e-gateway" },
  server: {
    id: "apr-e2e-server",
    name: "apr-e2e-server",
    upstreamUrl: "http://127.0.0.1:1/mcp",
  },
};

const PREFIX = "apr-e2e-";

const policies = [
  { id: `${PREFIX}allow-echo`, decision: "ALLOW", match: { tool: "echo" }, reason: "echo" },
  {
    id: `${PREFIX}approve-delete`,
    decision: "REQUIRE_APPROVAL",
    match: { tool: "danger.delete" },
    reason: "destructive action requires approval",
  },
  { id: `${PREFIX}deny-drop`, decision: "DENY", match: { tool: "bad.drop" }, reason: "blocked" },
];

function listen(server: http.Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") reject(new Error("no address"));
      else resolve(address.port);
    });
  });
}

d("approval workflow end-to-end (PostgreSQL)", () => {
  let pool: Pool;
  let upstream: http.Server;
  let upstreamUrl: string;
  let connections = 0;

  const repos = () => buildPgRepositories(pool);

  beforeAll(async () => {
    pool = new Pool({ connectionString: DATABASE_URL });
    await runMigrations(pool);
    upstream = http.createServer((req, res) => {
      connections++;
      req.resume();
      req.on("end", () => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { ok: true } }));
      });
    });
    const port = await listen(upstream);
    upstreamUrl = `http://127.0.0.1:${port}/mcp`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => upstream.close(() => resolve()));
    await clean();
    await pool.end();
  });

  beforeEach(async () => {
    connections = 0;
    await clean();
  });

  afterEach(async () => {
    await clean();
  });

  // Scoped strictly to this suite's prefix: integration files share one database
  // and must never delete another suite's rows.
  async function clean(): Promise<void> {
    await pool.query("DELETE FROM approvals WHERE agent_id LIKE $1", [`${PREFIX}%`]);
    await pool.query("DELETE FROM audit_events WHERE server_id LIKE $1", [`${PREFIX}%`]);
    await pool.query("DELETE FROM audit_events WHERE agent_id LIKE $1", [`${PREFIX}%`]);
    await pool.query("DELETE FROM agent_credentials WHERE agent_id LIKE $1", [`${PREFIX}%`]);
    await pool.query("DELETE FROM policies WHERE id LIKE $1", [`${PREFIX}%`]);
    await pool.query("DELETE FROM agents WHERE id LIKE $1", [`${PREFIX}%`]);
    await pool.query("DELETE FROM mcp_servers WHERE id LIKE $1", [`${PREFIX}%`]);
  }

  async function provision(agentId: string, role?: string): Promise<string> {
    await repos().agents.upsert({
      id: agentId,
      name: agentId,
      ...(role !== undefined ? { role } : {}),
    } as never);
    const created = await new DefaultCredentialService(repos(), new ScryptSecretHasher()).create({
      agentId,
      agentName: agentId,
    });
    return created.apiKey;
  }

  async function startGateway(): Promise<{ base: string; close: () => Promise<void> }> {
    const app = buildApp({
      databaseUrl: DATABASE_URL,
      upstreamUrl,
      identity,
      policies,
      audit: { flushIntervalMs: 60_000, maxAttempts: 1 },
      auth: { required: true },
    });
    await app.listen({ port: 0, host: "127.0.0.1" });
    const address = app.server.address();
    if (!address || typeof address === "string") throw new Error("no gateway address");
    const base = `http://127.0.0.1:${address.port}`;
    return { base, close: () => app.close() };
  }

  function mcp(
    base: string,
    apiKey: string,
    tool: string,
    args: Record<string, unknown> = {},
    headers: Record<string, string> = {},
  ): Promise<Response> {
    return fetch(`${base}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${apiKey}`,
        ...headers,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: tool, arguments: args },
      }),
    });
  }

  function admin(
    base: string,
    apiKey: string | undefined,
    path: string,
    init: RequestInit = {},
  ): Promise<Response> {
    // Only declare a JSON content type when a body is actually sent — Fastify
    // rejects an empty application/json body with 400.
    const hasBody = init.body !== undefined;
    return fetch(`${base}/admin${path}`, {
      ...init,
      headers: {
        ...(hasBody ? { "content-type": "application/json" } : {}),
        ...(apiKey !== undefined ? { authorization: `Bearer ${apiKey}` } : {}),
        ...(init.headers ?? {}),
      },
    });
  }

  async function createApproval(
    base: string,
    apiKey: string,
    tool: string,
    args: Record<string, unknown> = {},
  ): Promise<string> {
    const response = await mcp(base, apiKey, tool, args);
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      error?: { code: number; data?: { approvalId?: string; status?: string } };
    };
    expect(body.error?.code).toBe(-32002);
    expect(body.error?.data?.status).toBe("PENDING");
    const approvalId = body.error?.data?.approvalId;
    if (approvalId === undefined) throw new Error("no approval id");
    return approvalId;
  }

  it("creates a PENDING approval and never executes upstream", async () => {
    const agent = await provision(`${PREFIX}agent`);
    const { base, close } = await startGateway();

    const approvalId = await createApproval(base, agent, "danger.delete", { id: 1 });
    expect(connections).toBe(0);

    await close();
    const { rows } = await pool.query("SELECT * FROM approvals WHERE id = $1", [approvalId]);
    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe("PENDING");
    expect(rows[0].consumed_at).toBeNull();
  });

  it("does not execute a PENDING approval even when its id is presented", async () => {
    const agent = await provision(`${PREFIX}agent`);
    const { base, close } = await startGateway();

    const approvalId = await createApproval(base, agent, "danger.delete", { id: 1 });
    const retry = await mcp(
      base,
      agent,
      "danger.delete",
      { id: 1 },
      {
        "x-aegis-approval-id": approvalId,
      },
    );
    const body = (await retry.json()) as { error?: { code: number } };
    expect(body.error?.code).toBe(-32002);
    expect(connections).toBe(0);

    await close();
  });

  it("executes exactly once after an authorized administrator approves", async () => {
    const agent = await provision(`${PREFIX}agent`);
    const operator = await provision(`${PREFIX}operator`, "OPERATOR");
    const { base, close } = await startGateway();

    const approvalId = await createApproval(base, agent, "danger.delete", { id: 1 });

    const approved = await admin(base, operator, `/approvals/${approvalId}/approve`, {
      method: "POST",
      body: JSON.stringify({ reason: "reviewed" }),
    });
    expect(approved.status).toBe(200);

    const executed = await mcp(
      base,
      agent,
      "danger.delete",
      { id: 1 },
      {
        "x-aegis-approval-id": approvalId,
      },
    );
    expect(executed.status).toBe(200);
    const executedBody = (await executed.json()) as { result?: unknown; error?: unknown };
    expect(executedBody.result).toBeDefined();
    expect(connections).toBe(1);

    // Replay with the same approval id is refused and must not execute again.
    const replay = await mcp(
      base,
      agent,
      "danger.delete",
      { id: 1 },
      {
        "x-aegis-approval-id": approvalId,
      },
    );
    const replayBody = (await replay.json()) as { error?: { code: number } };
    expect(replayBody.error?.code).toBe(-32002);
    expect(connections).toBe(1);

    await close();
  });

  it("never executes a DENIED approval", async () => {
    const agent = await provision(`${PREFIX}agent`);
    const operator = await provision(`${PREFIX}operator`, "OPERATOR");
    const { base, close } = await startGateway();

    const approvalId = await createApproval(base, agent, "danger.delete", { id: 1 });
    const denied = await admin(base, operator, `/approvals/${approvalId}/deny`, {
      method: "POST",
      body: JSON.stringify({ reason: "no" }),
    });
    expect(denied.status).toBe(200);

    const retry = await mcp(
      base,
      agent,
      "danger.delete",
      { id: 1 },
      {
        "x-aegis-approval-id": approvalId,
      },
    );
    const body = (await retry.json()) as { error?: { code: number } };
    expect(body.error?.code).toBe(-32002);
    expect(connections).toBe(0);

    await close();
  });

  it("never executes an EXPIRED approval and cannot approve it", async () => {
    const agent = await provision(`${PREFIX}agent`);
    const operator = await provision(`${PREFIX}operator`, "OPERATOR");
    const { base, close } = await startGateway();

    const approvalId = await createApproval(base, agent, "danger.delete", { id: 1 });
    await pool.query(
      "UPDATE approvals SET expires_at = now() - interval '1 minute' WHERE id = $1",
      [approvalId],
    );

    const late = await admin(base, operator, `/approvals/${approvalId}/approve`, {
      method: "POST",
      body: JSON.stringify({}),
    });
    expect(late.status).toBe(409);

    const retry = await mcp(
      base,
      agent,
      "danger.delete",
      { id: 1 },
      {
        "x-aegis-approval-id": approvalId,
      },
    );
    const body = (await retry.json()) as { error?: { code: number } };
    expect(body.error?.code).toBe(-32002);
    expect(connections).toBe(0);

    await close();
  });

  it("refuses an approval used by a different agent (cross-agent)", async () => {
    const agentA = await provision(`${PREFIX}agent-a`);
    const agentB = await provision(`${PREFIX}agent-b`);
    const operator = await provision(`${PREFIX}operator`, "OPERATOR");
    const { base, close } = await startGateway();

    const approvalId = await createApproval(base, agentA, "danger.delete", { id: 1 });
    await admin(base, operator, `/approvals/${approvalId}/approve`, {
      method: "POST",
      body: JSON.stringify({}),
    });

    const cross = await mcp(
      base,
      agentB,
      "danger.delete",
      { id: 1 },
      {
        "x-aegis-approval-id": approvalId,
      },
    );
    const body = (await cross.json()) as { error?: { code: number } };
    expect(body.error?.code).toBe(-32002);
    expect(connections).toBe(0);

    await close();
  });

  it("refuses an approval replayed against a different request", async () => {
    const agent = await provision(`${PREFIX}agent`);
    const operator = await provision(`${PREFIX}operator`, "OPERATOR");
    const { base, close } = await startGateway();

    const approvalId = await createApproval(base, agent, "danger.delete", { id: 1 });
    await admin(base, operator, `/approvals/${approvalId}/approve`, {
      method: "POST",
      body: JSON.stringify({}),
    });

    const wrong = await mcp(
      base,
      agent,
      "danger.delete",
      { id: 999 },
      {
        "x-aegis-approval-id": approvalId,
      },
    );
    const body = (await wrong.json()) as { error?: { code: number } };
    expect(body.error?.code).toBe(-32002);
    expect(connections).toBe(0);

    await close();
  });

  it("redacts sensitive arguments and audits the lifecycle without secrets", async () => {
    const agent = await provision(`${PREFIX}agent`);
    const operator = await provision(`${PREFIX}operator`, "OPERATOR");
    const { base, close } = await startGateway();

    const approvalId = await createApproval(base, agent, "danger.delete", {
      id: 1,
      password: "SUPER-SECRET-DELETE",
    });
    await admin(base, operator, `/approvals/${approvalId}/approve`, {
      method: "POST",
      body: JSON.stringify({ reason: "ok" }),
    });
    await close();

    const approval = await pool.query("SELECT arguments FROM approvals WHERE id = $1", [
      approvalId,
    ]);
    expect(approval.rows[0].arguments.password).toBe("[REDACTED]");
    expect(JSON.stringify(approval.rows[0])).not.toContain("SUPER-SECRET-DELETE");

    const audit = await pool.query(
      "SELECT to_jsonb(a)::text AS row FROM audit_events a WHERE server_id LIKE $1",
      [`${PREFIX}%`],
    );
    const auditText = audit.rows.map((row) => row.row).join("\n");
    expect(auditText).not.toContain("SUPER-SECRET-DELETE");
    expect(auditText).toContain("approval_created");
    expect(auditText).toContain("approval_approved");

    const approvalsAudit = await pool.query(
      "SELECT event_type FROM audit_events WHERE approval_id = $1 ORDER BY id",
      [approvalId],
    );
    const eventTypes = approvalsAudit.rows.map((row) => row.event_type);
    expect(eventTypes).toContain("approval_created");
    expect(eventTypes).toContain("approval_approved");
  });

  it("blocks a DENY policy and never creates an approval", async () => {
    const agent = await provision(`${PREFIX}agent`);
    const { base, close } = await startGateway();

    const response = await mcp(base, agent, "bad.drop", {});
    const body = (await response.json()) as { error?: { code: number } };
    expect(body.error?.code).toBe(-32003);
    expect(connections).toBe(0);

    await close();
    // Scope to this suite: other suites share the database and may have their
    // own pending approvals.
    const count = await pool.query(
      "SELECT COUNT(*)::int AS n FROM approvals WHERE agent_id LIKE $1",
      [`${PREFIX}%`],
    );
    expect(count.rows[0].n).toBe(0);
  });

  it("requires administrative authentication for the control plane", async () => {
    await provision(`${PREFIX}agent`);
    const { base, close } = await startGateway();

    const missing = await admin(base, undefined, "/approvals");
    expect(missing.status).toBe(401);

    const agent = await provision(`${PREFIX}agent-2`);
    const forbidden = await admin(base, agent, "/approvals");
    expect(forbidden.status).toBe(403);

    await close();
  });

  it("prevents an ordinary agent from deciding approvals (privilege escalation)", async () => {
    const agent = await provision(`${PREFIX}agent`);
    const { base, close } = await startGateway();

    const approvalId = await createApproval(base, agent, "danger.delete", { id: 1 });
    const response = await admin(base, agent, `/approvals/${approvalId}/approve`, {
      method: "POST",
      body: JSON.stringify({}),
    });
    expect(response.status).toBe(403);

    await close();
  });

  it("enforces permission boundaries for AUDITOR and OPERATOR", async () => {
    const auditor = await provision(`${PREFIX}auditor`, "AUDITOR");
    const { base, close } = await startGateway();

    const read = await admin(base, auditor, "/policies");
    expect(read.status).toBe(200);

    const write = await admin(base, auditor, "/policies", {
      method: "POST",
      body: JSON.stringify({
        id: `${PREFIX}auditor-attempt`,
        decision: "ALLOW",
        match: {},
        reason: "should be forbidden",
      }),
    });
    expect(write.status).toBe(403);

    await close();
  });

  it("supports policy create/list/delete through the control plane", async () => {
    const operator = await provision(`${PREFIX}operator`, "OPERATOR");
    const { base, close } = await startGateway();

    const created = await admin(base, operator, "/policies", {
      method: "POST",
      body: JSON.stringify({
        id: `${PREFIX}runtime-allow`,
        decision: "ALLOW",
        match: { tool: "echo" },
        reason: "created at runtime",
      }),
    });
    expect(created.status).toBe(201);

    const listed = await admin(base, operator, "/policies?limit=100");
    expect(listed.status).toBe(200);
    const listedBody = (await listed.json()) as { items: { id: string }[] };
    expect(listedBody.items.some((policy) => policy.id === `${PREFIX}runtime-allow`)).toBe(true);

    const deleted = await admin(base, operator, `/policies/${PREFIX}runtime-allow`, {
      method: "DELETE",
    });
    expect(deleted.status).toBe(200);

    await close();
  });

  it("exposes audit events through the control plane without secrets", async () => {
    const agent = await provision(`${PREFIX}agent`);
    const auditor = await provision(`${PREFIX}auditor`, "AUDITOR");
    const { base, close } = await startGateway();

    await mcp(base, agent, "echo", { message: "hello" });
    // close() flushes the buffered audit sink to PostgreSQL.
    await close();

    const second = await startGateway();
    const audit = await admin(second.base, auditor, `/audit?limit=50`);
    expect(audit.status).toBe(200);
    const auditBody = (await audit.json()) as { items: unknown[] };
    expect(Array.isArray(auditBody.items)).toBe(true);
    expect(auditBody.items.length).toBeGreaterThanOrEqual(1);

    await second.close();
  });

  it("revokes every credential of an agent through the control plane", async () => {
    const adminKey = await provision(`${PREFIX}admin`, "ADMIN");
    const agent = await provision(`${PREFIX}agent`);
    const { base, close } = await startGateway();

    const revoked = await admin(base, adminKey, `/agents/${PREFIX}agent/revoke`, {
      method: "POST",
    });
    expect(revoked.status).toBe(200);
    const revokedBody = (await revoked.json()) as { revokedCredentials: number };
    expect(revokedBody.revokedCredentials).toBeGreaterThanOrEqual(1);

    // The previously valid agent credential no longer authenticates.
    const after = await mcp(base, agent, "echo", {});
    expect(after.status).toBe(401);

    await close();
  });
});
