import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { SecurityHarness, hasDb } from "./helpers.js";
import { parseApiKey } from "@aegis/gateway/security";

const d = describe.skipIf(!hasDb);

const PREFIX = "sec-redact-";
const TOOL = `${PREFIX}delete`;
const policies = [
  {
    id: `${PREFIX}require`,
    decision: "REQUIRE_APPROVAL" as const,
    match: { tool: TOOL },
    reason: "approval needed",
  },
];

const SECRET_ARG = "SUPER-SECRET-DELETE-VALUE";
const SECRET_TOKEN = "SUPER-SECRET-TOKEN";
const SECRET_KEY = "SUPER-SECRET-APIKEY";

d("SECURITY: sensitive data never leaks", () => {
  const h = new SecurityHarness(PREFIX, policies);

  beforeAll(() => h.setup());
  afterAll(() => h.teardown());
  beforeEach(() => h.clean());

  it("redacts sensitive tool arguments in the approval record and all responses", async () => {
    const agent = await h.provision(`${PREFIX}agent`);
    const operator = await h.provision(`${PREFIX}operator`, "OPERATOR");
    const gw = await h.startGateway();

    const args = {
      id: 7,
      password: SECRET_ARG,
      nested: { token: SECRET_TOKEN },
      apiKey: SECRET_KEY,
      safe: "keep-me",
    };
    const { approvalId } = await h.createApproval(gw.base, agent, TOOL, args);

    // Control-plane read must expose only redacted arguments.
    const detail = await h.admin(gw.base, operator, `/approvals/${approvalId}`);
    expect(detail.status).toBe(200);
    const detailText = await detail.text();
    for (const secret of [SECRET_ARG, SECRET_TOKEN, SECRET_KEY]) {
      expect(detailText).not.toContain(secret);
    }
    expect(detailText).toContain("[REDACTED]");
    expect(detailText).toContain("keep-me");

    await h.approveVia(gw.base, operator, approvalId);
    await h.mcp(gw.base, agent, TOOL, args, { "x-aegis-approval-id": approvalId });
    await gw.close();

    // Database: approval record and every audit row are secret-free.
    const approval = await h.approvalRow(approvalId);
    const approvalText = JSON.stringify(approval);
    expect(approvalText).not.toContain(SECRET_ARG);
    expect(approvalText).not.toContain(SECRET_TOKEN);
    expect(approvalText).not.toContain(SECRET_KEY);
    expect((approval?.arguments as Record<string, unknown>).password).toBe("[REDACTED]");
    expect(
      ((approval?.arguments as Record<string, unknown>).nested as Record<string, unknown>).token,
    ).toBe("[REDACTED]");

    const audit = await h.pool.query(
      "SELECT to_jsonb(a)::text AS row FROM audit_events a WHERE server_id LIKE $1",
      [`${PREFIX}%`],
    );
    const auditText = audit.rows.map((r) => r.row).join("\n");
    for (const secret of [SECRET_ARG, SECRET_TOKEN, SECRET_KEY]) {
      expect(auditText).not.toContain(secret);
    }
  });

  it("never persists a raw credential secret", async () => {
    const agent = `${PREFIX}agent`;
    const apiKey = await h.provision(agent);
    const secret = parseApiKey(apiKey)!.secret;
    const gw = await h.startGateway();

    await h.mcp(gw.base, agent, TOOL, { password: "x" });
    await gw.close();

    const audit = await h.pool.query(
      "SELECT to_jsonb(a)::text AS row FROM audit_events a WHERE server_id LIKE $1",
      [`${PREFIX}%`],
    );
    expect(audit.rows.map((r) => r.row).join("\n")).not.toContain(secret);

    const creds = await h.pool.query("SELECT * FROM agent_credentials WHERE agent_id LIKE $1", [
      `${PREFIX}%`,
    ]);
    const credsText = JSON.stringify(creds.rows);
    expect(credsText).not.toContain(secret);
    // Hashes/salts are stored, but the raw secret is not.
    expect(creds.rows[0]?.secret_hash).toBeTruthy();
  });

  it("does not echo presented credentials in any error response", async () => {
    const gw = await h.startGateway();
    const bogus = "amcp_" + "b".repeat(32) + "_" + "c".repeat(64);

    const mcpRes = await h.mcp(gw.base, bogus, TOOL);
    expect(mcpRes.status).toBe(401);
    expect(await mcpRes.text()).not.toContain(bogus);

    const adminRes = await h.admin(gw.base, bogus, "/approvals");
    expect(adminRes.status).toBe(401);
    expect(await adminRes.text()).not.toContain(bogus);

    await gw.close();
  });
});
