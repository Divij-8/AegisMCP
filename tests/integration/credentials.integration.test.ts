import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "@aegis/gateway/db";
import { buildPgRepositories } from "@aegis/gateway/repositories/pg";
import {
  DbAgentAuthenticator,
  DefaultCredentialService,
  ScryptSecretHasher,
  formatApiKey,
  generateKeyId,
  generateSecret,
  parseApiKey,
} from "@aegis/gateway/security";

const DATABASE_URL = process.env.DATABASE_URL;
const hasDb = typeof DATABASE_URL === "string" && DATABASE_URL.length > 0;

const d = describe.skipIf(!hasDb);

d("agent credentials (PostgreSQL)", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: DATABASE_URL });
    await runMigrations(pool);
    await clean();
  });

  afterAll(async () => {
    if (pool) {
      await clean();
      await pool.end();
    }
  });

  async function clean(): Promise<void> {
    // audit_events references agents and servers (FK, server_id NOT NULL), so
    // audit rows must go first — including auth failures that have a null
    // agent but a concrete server.
    await pool.query(
      "DELETE FROM audit_events WHERE key_id IN (SELECT key_id FROM agent_credentials WHERE agent_id LIKE 'cred-%')",
    );
    await pool.query("DELETE FROM audit_events WHERE agent_id LIKE 'cred-%'");
    await pool.query("DELETE FROM audit_events WHERE server_id LIKE 'cred-%'");
    await pool.query("DELETE FROM agent_credentials WHERE agent_id LIKE 'cred-%'");
    await pool.query("DELETE FROM policies WHERE id LIKE 'cred-%'");
    await pool.query("DELETE FROM agents WHERE id LIKE 'cred-%'");
    await pool.query("DELETE FROM mcp_servers WHERE id LIKE 'cred-%'");
  }

  function makeService(): {
    service: DefaultCredentialService;
    repositories: ReturnType<typeof buildPgRepositories>;
    hasher: ScryptSecretHasher;
  } {
    const repositories = buildPgRepositories(pool);
    const hasher = new ScryptSecretHasher();
    return { service: new DefaultCredentialService(repositories, hasher), repositories, hasher };
  }

  it("stores only a hash and resolves the registry agent on lookup", async () => {
    const { service, repositories } = makeService();
    const created = await service.create({
      agentId: "cred-agent",
      agentName: "Credential Agent",
      label: "primary",
    });
    const secret = parseApiKey(created.apiKey)!.secret;

    const record = await repositories.credentials.findByKeyId(created.keyId);
    expect(record).not.toBeNull();
    expect(record?.agent).toEqual({ id: "cred-agent", name: "Credential Agent" });
    expect(record?.label).toBe("primary");
    expect(record?.hashAlgo).toBe("scrypt-v1");
    expect(record?.revokedAt).toBeNull();
    expect(record?.createdAt).toBeGreaterThan(0);
    expect(record?.secretHash).not.toBe(secret);
    expect(record?.secretHash).not.toContain(secret);

    // The plaintext secret must not appear in ANY stored credential row.
    const { rows } = await pool.query("SELECT * FROM agent_credentials");
    for (const row of rows) {
      expect(JSON.stringify(row)).not.toContain(secret);
    }
  });

  it("revokes softly and idempotently", async () => {
    const { service, repositories } = makeService();
    const created = await service.create({ agentId: "cred-agent" });

    await expect(service.revoke(created.keyId)).resolves.toBe(true);
    const revoked = await repositories.credentials.findByKeyId(created.keyId);
    expect(revoked?.revokedAt).not.toBeNull();
    await expect(service.revoke(created.keyId)).resolves.toBe(false);
  });

  it("authenticates valid, unknown, invalid, and revoked credentials with real scrypt", async () => {
    const { service, repositories, hasher } = makeService();
    const created = await service.create({ agentId: "cred-agent" });
    const authenticator = new DbAgentAuthenticator(repositories.credentials, hasher);

    const valid = await authenticator.authenticate(created.apiKey);
    expect(valid.ok).toBe(true);
    if (valid.ok) expect(valid.credential.agent.id).toBe("cred-agent");

    const unknown = await authenticator.authenticate(
      formatApiKey(generateKeyId(), generateSecret()),
    );
    expect(unknown.ok).toBe(false);
    if (!unknown.ok) expect(unknown.reason).toBe("unknown");

    const keyId = parseApiKey(created.apiKey)!.keyId;
    const wrongSecret = await authenticator.authenticate(formatApiKey(keyId, generateSecret()));
    expect(wrongSecret.ok).toBe(false);
    if (!wrongSecret.ok) expect(wrongSecret.reason).toBe("invalid");

    await service.revoke(created.keyId);
    const revoked = await authenticator.authenticate(created.apiKey);
    expect(revoked.ok).toBe(false);
    if (!revoked.ok) expect(revoked.reason).toBe("revoked");
  });

  it("enforces the agent foreign key", async () => {
    const { repositories } = makeService();
    await expect(
      repositories.credentials.create({
        keyId: generateKeyId(),
        agent: { id: "cred-does-not-exist", name: "missing" },
        secretHash: "00",
        salt: "00",
        hashAlgo: "scrypt-v1",
        createdAt: Date.now(),
        expiresAt: null,
      }),
    ).rejects.toThrow();
  });

  it("accepts auth failures with a null agent and rejects unknown reasons", async () => {
    const { repositories } = makeService();
    await repositories.servers.upsert({
      id: "cred-server",
      name: "cred-server",
      upstreamUrl: "http://127.0.0.1:1/mcp",
    });
    const keyId = generateKeyId();

    await repositories.auditEvents.insertBatch([
      {
        eventType: "auth",
        requestId: "cred-req-1",
        occurredAt: Date.now(),
        agentId: null,
        serverId: "cred-server",
        method: "tools/list",
        toolName: undefined,
        decision: null,
        policyId: null,
        reason: "Authentication failed: no credential presented",
        outcome: "auth_failed",
        upstreamStatus: null,
        latencyMs: 2,
        keyId,
        authFailureReason: "missing",
      },
    ]);

    const { rows } = await pool.query("SELECT * FROM audit_events WHERE request_id = 'cred-req-1'");
    expect(rows).toHaveLength(1);
    const row = rows[0] as Record<string, unknown>;
    expect(row["event_type"]).toBe("auth");
    expect(row["outcome"]).toBe("auth_failed");
    expect(row["agent_id"]).toBeNull();
    expect(row["auth_failure_reason"]).toBe("missing");
    expect(row["key_id"]).toBe(keyId);

    await expect(
      pool.query(
        `INSERT INTO audit_events
           (event_type, occurred_at, server_id, method, reason, outcome, latency_ms, auth_failure_reason)
         VALUES ('auth', now(), 'cred-server', 'tools/list', 'x', 'auth_failed', 1, 'bogus')`,
      ),
    ).rejects.toThrow();
  });
});
