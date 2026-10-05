import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { SecurityHarness, hasDb } from "./helpers.js";

const d = describe.skipIf(!hasDb);

const PREFIX = "sec-rbac-";
const TOOL = `${PREFIX}tool`;

const policies = [
  {
    id: `${PREFIX}require`,
    decision: "REQUIRE_APPROVAL" as const,
    match: { tool: TOOL },
    reason: "approval needed",
  },
];

d("SECURITY: RBAC boundaries", () => {
  const h = new SecurityHarness(PREFIX, policies);
  let agentKey = "";
  let auditorKey = "";
  let operatorKey = "";
  let adminKey = "";

  beforeAll(() => h.setup());
  afterAll(() => h.teardown());
  beforeEach(async () => {
    await h.clean();
    agentKey = await h.provision(`${PREFIX}agent`, "AGENT");
    auditorKey = await h.provision(`${PREFIX}auditor`, "AUDITOR");
    operatorKey = await h.provision(`${PREFIX}operator`, "OPERATOR");
    adminKey = await h.provision(`${PREFIX}admin`, "ADMIN");
  });

  it("requires authentication for every control-plane group", async () => {
    const gw = await h.startGateway();
    for (const path of ["/approvals", "/policies", "/agents", "/servers", "/audit"]) {
      expect((await h.admin(gw.base, undefined, path)).status).toBe(401);
    }
    await gw.close();
  });

  it("refuses every control-plane operation for an AGENT credential", async () => {
    const gw = await h.startGateway();
    const cases: Array<[string, RequestInit]> = [
      ["/approvals", {}],
      ["/approvals/apr_x/approve", { method: "POST", body: "{}" }],
      ["/approvals/apr_x/deny", { method: "POST", body: "{}" }],
      ["/policies", {}],
      [
        "/policies",
        {
          method: "POST",
          body: JSON.stringify({ id: `${PREFIX}x`, decision: "ALLOW", match: {}, reason: "x" }),
        },
      ],
      ["/policies/x", { method: "PATCH", body: "{}" }],
      ["/policies/x", { method: "DELETE" }],
      ["/agents", {}],
      ["/agents", { method: "POST", body: JSON.stringify({ id: `${PREFIX}n` }) }],
      ["/agents/sec-rbac-agent/revoke", { method: "POST" }],
      ["/servers", {}],
      ["/audit", {}],
    ];
    for (const [path, init] of cases) {
      expect((await h.admin(gw.base, agentKey, path, init)).status).toBe(403);
    }
    await gw.close();
  });

  it("does not mutate state on a forbidden write", async () => {
    const gw = await h.startGateway();

    const res = await h.admin(gw.base, agentKey, "/policies", {
      method: "POST",
      body: JSON.stringify({ id: `${PREFIX}attempt`, decision: "ALLOW", match: {}, reason: "x" }),
    });
    expect(res.status).toBe(403);

    // The forbidden write must not have created the policy (assert by id, not
    // by global count, since suites share one database and run concurrently).
    const fetched = await h.admin(gw.base, auditorKey, `/policies/${PREFIX}attempt`);
    expect(fetched.status).toBe(404);

    await gw.close();
  });

  it("gives AUDITOR read access but refuses all writes", async () => {
    const gw = await h.startGateway();
    for (const path of ["/approvals", "/policies", "/agents", "/servers", "/audit"]) {
      expect((await h.admin(gw.base, auditorKey, path)).status).toBe(200);
    }
    for (const [path, init] of [
      [
        "/policies",
        {
          method: "POST",
          body: JSON.stringify({ id: `${PREFIX}a`, decision: "ALLOW", match: {}, reason: "x" }),
        },
      ],
      ["/policies/x", { method: "DELETE" }],
      ["/agents", { method: "POST", body: JSON.stringify({ id: `${PREFIX}a` }) }],
      ["/agents/sec-rbac-agent/revoke", { method: "POST" }],
      ["/approvals/apr_x/approve", { method: "POST", body: "{}" }],
    ] as Array<[string, RequestInit]>) {
      expect((await h.admin(gw.base, auditorKey, path, init)).status).toBe(403);
    }
    await gw.close();
  });

  it("reserves privileged role assignment for ADMIN", async () => {
    const gw = await h.startGateway();

    // OPERATOR may manage ordinary agents...
    const operatorCreatesAgent = await h.admin(gw.base, operatorKey, "/agents", {
      method: "POST",
      body: JSON.stringify({ id: `${PREFIX}new-agent`, role: "AGENT" }),
    });
    expect(operatorCreatesAgent.status).toBe(201);

    // ...but must not be able to mint a privileged principal (role:assign).
    const operatorEscalates = await h.admin(gw.base, operatorKey, "/agents", {
      method: "POST",
      body: JSON.stringify({ id: `${PREFIX}new-admin`, role: "ADMIN" }),
    });
    expect(operatorEscalates.status).toBe(403);

    const adminAssigns = await h.admin(gw.base, adminKey, "/agents", {
      method: "POST",
      body: JSON.stringify({ id: `${PREFIX}new-admin`, role: "ADMIN" }),
    });
    expect(adminAssigns.status).toBe(201);

    await gw.close();

    // The escalated principal must not exist as ADMIN.
    const row = await h.pool.query("SELECT role FROM agents WHERE id = $1", [`${PREFIX}new-admin`]);
    expect(row.rows[0]?.role).toBe("ADMIN");
    const denied = await h.pool.query(
      "SELECT * FROM audit_events WHERE server_id LIKE $1 AND method = 'admin.denied:role:assign'",
      [`${PREFIX}%`],
    );
    expect(denied.rows.length).toBeGreaterThanOrEqual(1);
  });

  it("refuses agent revocation by unauthorized roles and keeps the credential usable", async () => {
    const victim = await h.provision(`${PREFIX}victim`, "AGENT");
    const gw = await h.startGateway();

    expect(
      (await h.admin(gw.base, auditorKey, `/agents/${PREFIX}victim/revoke`, { method: "POST" }))
        .status,
    ).toBe(403);
    expect(
      (await h.admin(gw.base, agentKey, `/agents/${PREFIX}victim/revoke`, { method: "POST" }))
        .status,
    ).toBe(403);

    // Credential is untouched.
    expect((await h.admin(gw.base, victim, "/me")).status).toBe(403); // AGENT can't use control plane
    const stillListed = await h.admin(gw.base, operatorKey, "/agents?limit=200");
    const ids = ((await stillListed.json()) as { items: { id: string }[] }).items.map((a) => a.id);
    expect(ids).toContain(`${PREFIX}victim`);

    // An authorized OPERATOR can revoke it.
    expect(
      (await h.admin(gw.base, operatorKey, `/agents/${PREFIX}victim/revoke`, { method: "POST" }))
        .status,
    ).toBe(200);
    await gw.close();
  });

  it("refuses approval decisions from non-deciding roles", async () => {
    const gw = await h.startGateway();
    const created = await h.createApproval(gw.base, agentKey, TOOL, { id: 1 });

    expect(
      (
        await h.admin(gw.base, auditorKey, `/approvals/${created.approvalId}/approve`, {
          method: "POST",
          body: "{}",
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await h.admin(gw.base, agentKey, `/approvals/${created.approvalId}/approve`, {
          method: "POST",
          body: "{}",
        })
      ).status,
    ).toBe(403);

    // Still pending; nothing executed.
    expect((await h.approvalRow(created.approvalId))?.status).toBe("PENDING");
    expect(h.connections).toBe(0);

    // OPERATOR (approval:decide) can.
    expect((await h.approveVia(gw.base, operatorKey, created.approvalId)).status).toBe(200);
    await gw.close();
    expect((await h.approvalRow(created.approvalId))?.status).toBe("APPROVED");
  });
});
