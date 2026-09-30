import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import http from "node:http";
import { Pool } from "pg";
import { buildApp } from "@aegis/gateway/app";
import { runMigrations } from "@aegis/gateway/db";
import { buildPgRepositories } from "@aegis/gateway/repositories/pg";
import {
  DefaultCredentialService,
  ScryptSecretHasher,
  formatApiKey,
  generateKeyId,
  generateSecret,
  parseApiKey,
} from "@aegis/gateway/security";

/** Structural mirror of the gateway Policy type (tests are not typechecked). */
type Policy = {
  readonly id: string;
  readonly decision: "ALLOW" | "DENY" | "REQUIRE_APPROVAL";
  readonly match: { readonly tool?: string };
  readonly reason: string;
};

const DATABASE_URL = process.env.DATABASE_URL;
const hasDb = typeof DATABASE_URL === "string" && DATABASE_URL.length > 0;

const d = describe.skipIf(!hasDb);

const identity = {
  agent: { id: "auth-e2e-agent", name: "auth-e2e-agent" },
  server: { id: "auth-e2e-server", name: "auth-e2e-server", upstreamUrl: "http://127.0.0.1:1/mcp" },
};

const TOOL = "auth-e2e-tool";

const allowPolicy: Policy = {
  id: "auth-e2e-allow",
  decision: "ALLOW",
  match: { tool: TOOL },
  reason: "auth e2e allow",
};

const denyPolicy: Policy = {
  id: "auth-e2e-deny",
  decision: "DENY",
  match: { tool: TOOL },
  reason: "auth e2e deny",
};

function listen(server: http.Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") reject(new Error("no address"));
      else resolve(address.port);
    });
  });
}

d("gateway authentication end-to-end (PostgreSQL)", () => {
  let pool: Pool;
  let upstream: http.Server;
  let upstreamUrl: string;
  let connections = 0;

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

  async function clean(): Promise<void> {
    // audit_events references agents and servers (FK, server_id NOT NULL), so
    // audit rows must go first — including auth failures that have a null
    // agent but a concrete server.
    await pool.query(
      "DELETE FROM audit_events WHERE key_id IN (SELECT key_id FROM agent_credentials WHERE agent_id LIKE 'auth-e2e-%')",
    );
    await pool.query("DELETE FROM audit_events WHERE agent_id LIKE 'auth-e2e-%'");
    await pool.query("DELETE FROM audit_events WHERE server_id LIKE 'auth-e2e-%'");
    await pool.query("DELETE FROM agent_credentials WHERE agent_id LIKE 'auth-e2e-%'");
    await pool.query("DELETE FROM policies WHERE id LIKE 'auth-e2e-%'");
    await pool.query("DELETE FROM agents WHERE id LIKE 'auth-e2e-%'");
    await pool.query("DELETE FROM mcp_servers WHERE id LIKE 'auth-e2e-%'");
  }

  function makeService(): DefaultCredentialService {
    return new DefaultCredentialService(buildPgRepositories(pool), new ScryptSecretHasher());
  }

  async function startGateway(options: {
    required?: boolean;
    policies?: readonly Policy[];
  }): Promise<{ url: string; close: () => Promise<void> }> {
    const gateway = buildApp({
      databaseUrl: DATABASE_URL,
      upstreamUrl,
      identity,
      policies: options.policies ?? [allowPolicy],
      audit: { flushIntervalMs: 60_000, maxAttempts: 1 },
      auth: { required: options.required ?? true },
    });
    await gateway.listen({ port: 0, host: "127.0.0.1" });
    const address = gateway.server.address();
    if (!address || typeof address === "string") throw new Error("no gateway address");
    return {
      url: `http://127.0.0.1:${address.port}/mcp`,
      close: () => gateway.close(),
    };
  }

  const toolCall = (id: string | number) =>
    JSON.stringify({
      jsonrpc: "2.0",
      id,
      method: "tools/call",
      params: { name: TOOL, arguments: {} },
    });

  it("forwards an authenticated request and never persists the secret", async () => {
    const created = await makeService().create({
      agentId: "auth-e2e-agent",
      agentName: "auth-e2e-agent",
    });
    const secret = parseApiKey(created.apiKey)!.secret;

    const { url, close } = await startGateway({});
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${created.apiKey}`,
      },
      body: toolCall("auth-e2e-1"),
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as { result?: unknown; error?: unknown };
    expect(body.result).toBeDefined();
    expect(body.error).toBeUndefined();
    expect(connections).toBe(1);

    await close();

    const { rows } = await pool.query("SELECT * FROM audit_events WHERE request_id = 'auth-e2e-1'");
    expect(rows).toHaveLength(1);
    const row = rows[0] as Record<string, unknown>;
    expect(row["event_type"]).toBe("request");
    expect(row["agent_id"]).toBe("auth-e2e-agent");
    expect(row["outcome"]).toBe("forwarded");

    const all = await pool.query("SELECT * FROM audit_events");
    for (const auditRow of all.rows) {
      expect(JSON.stringify(auditRow)).not.toContain(secret);
    }
  });

  it("rejects a missing credential with 401 and never contacts upstream", async () => {
    const { url, close } = await startGateway({});

    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: toolCall("auth-e2e-missing"),
    });

    expect(response.status).toBe(401);
    const body = (await response.json()) as { error?: { code: number; message: string } };
    expect(body.error?.code).toBe(-32004);
    expect(body.error?.message).toBe("Missing credentials");
    expect(connections).toBe(0);

    await close();

    const { rows } = await pool.query(
      "SELECT * FROM audit_events WHERE request_id = 'auth-e2e-missing'",
    );
    expect(rows).toHaveLength(1);
    const row = rows[0] as Record<string, unknown>;
    expect(row["event_type"]).toBe("auth");
    expect(row["outcome"]).toBe("auth_failed");
    expect(row["auth_failure_reason"]).toBe("missing");
    expect(row["agent_id"]).toBeNull();
  });

  it("rejects a revoked credential with a generic 401 and audits the reason", async () => {
    const service = makeService();
    const created = await service.create({ agentId: "auth-e2e-agent" });
    await service.revoke(created.keyId);

    const { url, close } = await startGateway({});
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${created.apiKey}`,
      },
      body: toolCall("auth-e2e-revoked"),
    });

    expect(response.status).toBe(401);
    const body = (await response.json()) as { error?: { code: number; message: string } };
    expect(body.error?.code).toBe(-32004);
    // Generic — revoked and invalid are indistinguishable to the client.
    expect(body.error?.message).toBe("Authentication failed");
    expect(connections).toBe(0);

    await close();

    const { rows } = await pool.query("SELECT * FROM audit_events WHERE key_id = $1", [
      created.keyId,
    ]);
    expect(rows).toHaveLength(1);
    const row = rows[0] as Record<string, unknown>;
    expect(row["auth_failure_reason"]).toBe("revoked");
    expect(row["key_id"]).toBe(created.keyId);
  });

  it("rejects an unknown credential and audits the public key id only", async () => {
    const unknownKey = formatApiKey(generateKeyId(), generateSecret());

    const { url, close } = await startGateway({});
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${unknownKey}` },
      body: toolCall("auth-e2e-unknown"),
    });

    expect(response.status).toBe(401);
    expect(connections).toBe(0);

    await close();

    const keyId = parseApiKey(unknownKey)!.keyId;
    const { rows } = await pool.query("SELECT * FROM audit_events WHERE key_id = $1", [keyId]);
    expect(rows).toHaveLength(1);
    const row = rows[0] as Record<string, unknown>;
    expect(row["auth_failure_reason"]).toBe("unknown");
    expect(JSON.stringify(row)).not.toContain(parseApiKey(unknownKey)!.secret);
  });

  it("rejects an unauthenticated notification and never reaches upstream", async () => {
    const { url, close } = await startGateway({});

    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "notifications/cancelled",
        params: { requestId: 1 },
      }),
    });

    expect(response.status).toBe(401);
    expect(connections).toBe(0);

    await close();

    const { rows } = await pool.query(
      "SELECT * FROM audit_events WHERE event_type = 'auth' AND method = 'notifications/cancelled'",
    );
    expect(rows.length).toBeGreaterThanOrEqual(1);
    expect((rows[0] as Record<string, unknown>)["auth_failure_reason"]).toBe("missing");
  });

  it("enforces policy after a successful authentication", async () => {
    const created = await makeService().create({ agentId: "auth-e2e-agent" });

    const { url, close } = await startGateway({ policies: [denyPolicy] });
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${created.apiKey}`,
      },
      body: toolCall("auth-e2e-deny"),
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as { error?: { code: number } };
    // Authentication succeeded; the policy engine (unchanged) still denied.
    expect(body.error?.code).toBe(-32003);
    expect(connections).toBe(0);

    await close();
  });

  it("preserves unauthenticated behavior when AUTH_REQUIRED is false with a database", async () => {
    const { url, close } = await startGateway({ required: false });

    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: toolCall("auth-e2e-compat"),
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as { result?: unknown };
    expect(body.result).toBeDefined();
    expect(connections).toBe(1);

    await close();
  });
});
