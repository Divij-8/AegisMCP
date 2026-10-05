import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { Pool } from "pg";
import { buildApp } from "@aegis/gateway/app";
import { runMigrations } from "@aegis/gateway/db";

const DATABASE_URL = process.env.DATABASE_URL;
const hasDb = typeof DATABASE_URL === "string" && DATABASE_URL.length > 0;

const d = describe.skipIf(!hasDb);

const identity = {
  agent: { id: "e2e-agent", name: "e2e-agent" },
  server: {
    id: "e2e-server",
    name: "e2e-server",
    upstreamUrl: "http://127.0.0.1:1/mcp",
  },
};

function listen(server: http.Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") reject(new Error("no address"));
      else resolve(addr.port);
    });
  });
}

d("gateway persistence end-to-end (PostgreSQL)", () => {
  let pool: Pool;
  let upstream: http.Server;
  let upstreamPort: number;
  let upstreamUrl: string;

  beforeAll(async () => {
    pool = new Pool({ connectionString: DATABASE_URL });
    await runMigrations(pool);
    upstream = http.createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        const body = JSON.stringify({ jsonrpc: "2.0", id: 1, result: { ok: true } });
        res.writeHead(200, { "content-type": "application/json" });
        res.end(body);
      });
    });
    upstreamPort = await listen(upstream);
    upstreamUrl = `http://127.0.0.1:${upstreamPort}/mcp`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => upstream.close(() => resolve()));
    await pool.end();
  });

  async function clean(): Promise<void> {
    // Targeted cleanup: only this suite's rows (another DB suite runs in
    // parallel against the same database). All ids are namespaced e2e-*.
    await pool.query("DELETE FROM audit_events WHERE agent_id = 'e2e-agent'");
    await pool.query("DELETE FROM policies WHERE id LIKE 'e2e-%'");
    await pool.query("DELETE FROM agents WHERE id LIKE 'e2e-%'");
    await pool.query("DELETE FROM mcp_servers WHERE id LIKE 'e2e-%'");
  }

  it("seeds policies to DB, serves them, and records audit rows", async () => {
    await clean();

    const gateway = buildApp({
      databaseUrl: DATABASE_URL,
      upstreamUrl,
      identity,
      // A tool name unique to this suite keeps the policy assertion
      // independent of other suites sharing the database: the gateway loads
      // every enabled policy, so no foreign ALLOW may match this tool.
      policies: [
        {
          id: "e2e-allow-echo",
          decision: "ALLOW",
          match: { tool: "e2e-persist-echo" },
          reason: "seeded allow",
        },
      ],
      audit: { flushIntervalMs: 60_000, maxAttempts: 1 },
    });
    await gateway.listen({ port: 0, host: "127.0.0.1" });
    const addr = gateway.server.address();
    const url = `http://127.0.0.1:${addr && typeof addr !== "string" ? addr.port : 0}/mcp`;

    const resp = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "e2e-1",
        method: "tools/call",
        params: { name: "e2e-persist-echo", arguments: { secret: "DO-NOT-PERSIST" } },
      }),
    });
    // (request id is also namespaced for the same isolation reason)
    const body = (await resp.json()) as { result?: unknown; error?: unknown };
    expect(body.error).toBeUndefined();
    expect(body.result).toBeDefined();

    // Background interval is 60s in this test; close() must flush.
    await gateway.close();

    const { rows } = await pool.query("SELECT * FROM audit_events WHERE request_id = 'e2e-1'");
    expect(rows).toHaveLength(1);
    const row = rows[0] as Record<string, unknown>;
    expect(row["event_type"]).toBe("request");
    expect(row["decision"]).toBe("ALLOW");
    expect(row["outcome"]).toBe("forwarded");
    expect(row["upstream_status"]).toBe(200);
    expect(row["policy_id"]).toBe("e2e-allow-echo");
    expect(row["latency_ms"]).not.toBeNull();

    // Raw tool arguments must never appear in the audit trail.
    const all = await pool.query("SELECT * FROM audit_events");
    for (const row of all.rows) {
      expect(JSON.stringify(row)).not.toContain("DO-NOT-PERSIST");
    }

    // Seeded policy really is in the database.
    const policyRows = await pool.query("SELECT id FROM policies WHERE id = 'e2e-allow-echo'");
    expect(policyRows.rowCount).toBe(1);
  });

  it("disabling a policy in the DB changes gateway decisions after boot", async () => {
    await clean();

    // A tool name unique to this suite keeps the DENY assertion independent of
    // other suites sharing the database (no foreign policy can match it).
    const tool = "e2e-deny-check";

    const gateway = buildApp({
      databaseUrl: DATABASE_URL,
      upstreamUrl,
      identity,
      policies: [
        {
          id: "e2e-allow-denycheck",
          decision: "ALLOW",
          match: { tool },
          reason: "seeded allow",
        },
      ],
      audit: { flushIntervalMs: 60_000, maxAttempts: 1 },
    });
    await gateway.listen({ port: 0, host: "127.0.0.1" });
    const addr = gateway.server.address();
    const url = `http://127.0.0.1:${addr && typeof addr !== "string" ? addr.port : 0}/mcp`;

    // Disable only this suite's policies (scoped: never mutate other suites'
    // rows in the shared database). The unique tool name guarantees the request
    // then falls back to the fail-closed default DENY.
    await pool.query("UPDATE policies SET enabled = false WHERE id LIKE 'e2e-%'");
    // Runtime reload picks up the DB change without restart.
    const persistence = (
      gateway as unknown as { persistence: { policyStore: { reloadSafe(): Promise<boolean> } } }
    ).persistence;
    expect(persistence).not.toBeNull();
    await persistence.policyStore.reloadSafe();

    const resp = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 5,
        method: "tools/call",
        params: { name: tool, arguments: {} },
      }),
    });

    expect(resp.status).toBe(200);
    const body = (await resp.json()) as { error?: { code: number } };
    expect(body.error?.code).toBe(-32003);

    await gateway.close();
  });
});
