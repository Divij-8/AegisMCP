import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { SecurityHarness, hasDb } from "./helpers.js";
import { formatApiKey, generateKeyId, generateSecret, parseApiKey } from "@aegis/gateway/security";

const d = describe.skipIf(!hasDb);

const TOOL = "sec-auth-tool";
const policies = [
  {
    id: `sec-auth-${"allow"}`,
    decision: "ALLOW" as const,
    match: { tool: TOOL },
    reason: "auth suite",
  },
];

d("SECURITY: authentication attacks fail closed", () => {
  const h = new SecurityHarness("sec-auth-", policies);

  beforeAll(() => h.setup());
  afterAll(() => h.teardown());
  beforeEach(() => h.clean());

  async function start() {
    return h.startGateway();
  }

  it("rejects a missing credential with 401 and never contacts upstream", async () => {
    const gw = await start();
    const res = await h.mcp(gw.base, undefined, TOOL);
    expect(res.status).toBe(401);
    expect(h.connections).toBe(0);
    await gw.close();
  });

  it("rejects malformed credentials (generic 401, no echo of the presented value)", async () => {
    const gw = await start();
    const cases = [
      "not-a-key",
      "amcp_only-two",
      "amcp_a_b_c_d",
      "amcp_zzzz_zzzz",
      "Bearer",
      "amcp_" + "a".repeat(32) + "_" + "Z".repeat(64),
    ];
    for (const value of cases) {
      const res = await h.mcp(gw.base, undefined, TOOL, {}, { authorization: `Bearer ${value}` });
      expect(res.status).toBe(401);
      const text = JSON.stringify(await res.json());
      for (const fragment of ["not-a-key", "zzzz", "a_b_c", value.slice(0, 12)]) {
        expect(text).not.toContain(fragment);
      }
    }
    expect(h.connections).toBe(0);
    await gw.close();
  });

  it("rejects an unknown key id", async () => {
    const gw = await start();
    const unknown = formatApiKey(generateKeyId(), generateSecret());
    const res = await h.mcp(gw.base, unknown, TOOL);
    expect(res.status).toBe(401);
    expect(h.connections).toBe(0);
    await gw.close();
  });

  it("rejects a credential with a modified secret", async () => {
    const key = await h.provision(`${h.prefix}agent`);
    const parsed = parseApiKey(key)!;
    const flipped = (parsed.secret[0] === "a" ? "b" : "a") + parsed.secret.slice(1);
    const modified = formatApiKey(parsed.keyId, flipped);

    const gw = await start();
    const res = await h.mcp(gw.base, modified, TOOL);
    expect(res.status).toBe(401);
    expect(h.connections).toBe(0);
    await gw.close();
  });

  it("rejects a revoked credential", async () => {
    const key = await h.provisionWithState(`${h.prefix}agent`, { revoked: true });
    const gw = await start();
    const res = await h.mcp(gw.base, key, TOOL);
    expect(res.status).toBe(401);
    expect(h.connections).toBe(0);
    await gw.close();

    const rows = await h.pool.query(
      "SELECT auth_failure_reason FROM audit_events WHERE server_id LIKE $1 AND event_type = 'auth'",
      [`${h.prefix}%`],
    );
    expect(rows.rows.some((r) => r.auth_failure_reason === "revoked")).toBe(true);
  });

  it("rejects an expired credential", async () => {
    const key = await h.provisionWithState(`${h.prefix}agent`, { expiresAt: Date.now() - 1000 });
    const gw = await start();
    const res = await h.mcp(gw.base, key, TOOL);
    expect(res.status).toBe(401);
    expect(h.connections).toBe(0);
    await gw.close();

    const rows = await h.pool.query(
      "SELECT auth_failure_reason FROM audit_events WHERE server_id LIKE $1 AND event_type = 'auth'",
      [`${h.prefix}%`],
    );
    expect(rows.rows.some((r) => r.auth_failure_reason === "expired")).toBe(true);
  });

  it("accepts a valid credential, then rejects it after revocation (replay-after-revoke)", async () => {
    const agent = `${h.prefix}agent`;
    const key = await h.provision(agent);
    const gw = await start();

    const first = await h.mcp(gw.base, key, TOOL);
    expect(first.status).toBe(200);
    expect((await first.json()).result).toBeDefined();
    expect(h.connections).toBe(1);

    const parsed = parseApiKey(key)!;
    await h.repositories().credentials.revoke(parsed.keyId, Date.now());

    const second = await h.mcp(gw.base, key, TOOL);
    expect(second.status).toBe(401);
    expect(h.connections).toBe(1); // no new upstream execution

    await gw.close();
  });

  it("derives agent identity from the credential, ignoring spoofed headers and body fields", async () => {
    const agent = `${h.prefix}agent`;
    const key = await h.provision(agent);
    const gw = await start();

    const res = await h.mcp(
      gw.base,
      key,
      TOOL,
      { agentId: "someone-else" },
      {
        "x-agent-id": "someone-else",
        "x-agent-role": "ADMIN",
        "x-forwarded-user": "someone-else",
      },
    );
    expect(res.status).toBe(200);
    await gw.close();

    const rows = await h.pool.query(
      "SELECT agent_id FROM audit_events WHERE server_id LIKE $1 AND event_type = 'request'",
      [`${h.prefix}%`],
    );
    expect(rows.rows.every((r) => r.agent_id === agent)).toBe(true);
  });

  it("does not let spoofed role metadata elevate an AGENT credential", async () => {
    const key = await h.provision(`${h.prefix}agent`, "AGENT");
    const gw = await start();

    for (const headers of [
      { "x-agent-role": "ADMIN" },
      { "x-role": "ADMIN" },
      { "x-aegis-role": "ADMIN" },
      { "x-api-key": "" },
    ]) {
      const res = await h.admin(gw.base, key, "/approvals", { headers });
      expect(res.status).toBe(403);
    }
    await gw.close();
  });
});
