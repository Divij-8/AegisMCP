import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { SecurityHarness, hasDb } from "./helpers.js";

const d = describe.skipIf(!hasDb);

const PREFIX = "sec-appr-";
const SAFE = "sec-appr-safe";
const DELETE = "sec-appr-delete";
const OTHER = "sec-appr-other";

const policies = [
  { id: "sec-appr-allow-safe", decision: "ALLOW" as const, match: { tool: SAFE }, reason: "safe" },
  {
    id: "sec-appr-require-delete",
    decision: "REQUIRE_APPROVAL" as const,
    match: { tool: DELETE },
    reason: "destructive action requires approval",
  },
  {
    id: "sec-appr-require-other",
    decision: "REQUIRE_APPROVAL" as const,
    match: { tool: OTHER },
    reason: "other requires approval",
  },
  {
    id: "sec-appr-require-list",
    decision: "REQUIRE_APPROVAL" as const,
    match: { method: "tools/list" },
    reason: "listing requires approval",
  },
];

d("SECURITY: approval attacks", () => {
  const h = new SecurityHarness(PREFIX, policies);
  let agent = "";
  let otherAgent = "";
  let admin = "";

  beforeAll(async () => {
    await h.setup();
  });
  afterAll(() => h.teardown());

  beforeEach(async () => {
    await h.clean();
    agent = await h.provision(`${PREFIX}agent`);
    otherAgent = await h.provision(`${PREFIX}agent-b`);
    admin = await h.provision(`${PREFIX}admin`, "ADMIN");
  });

  it("creates a PENDING approval and executes nothing", async () => {
    const gw = await h.startGateway();
    const { approvalId } = await h.createApproval(gw.base, agent, DELETE, { id: 1 });
    expect(h.connections).toBe(0);
    expect((await h.approvalRow(approvalId))?.status).toBe("PENDING");
    await gw.close();
  });

  it("executes exactly once after approval; replay is refused", async () => {
    const gw = await h.startGateway();
    const { approvalId } = await h.createApproval(gw.base, agent, DELETE, { id: 1 });
    expect((await h.approveVia(gw.base, admin, approvalId)).status).toBe(200);

    const exec = await h.mcp(
      gw.base,
      agent,
      DELETE,
      { id: 1 },
      { "x-aegis-approval-id": approvalId },
    );
    expect(exec.status).toBe(200);
    expect(h.connections).toBe(1);

    const replay = await h.mcp(
      gw.base,
      agent,
      DELETE,
      { id: 1 },
      { "x-aegis-approval-id": approvalId },
    );
    const body = (await replay.json()) as { error?: { code: number } };
    expect(body.error?.code).toBe(-32002);
    expect(h.connections).toBe(1);

    await gw.close();
    expect((await h.approvalRow(approvalId))?.consumed_at).not.toBeNull();
  });

  it("never executes a pending approval even when its id is presented", async () => {
    const gw = await h.startGateway();
    const { approvalId } = await h.createApproval(gw.base, agent, DELETE, { id: 1 });
    const res = await h.mcp(
      gw.base,
      agent,
      DELETE,
      { id: 1 },
      { "x-aegis-approval-id": approvalId },
    );
    expect(((await res.json()) as { error?: { code: number } }).error?.code).toBe(-32002);
    expect(h.connections).toBe(0);
    await gw.close();
  });

  it("never executes a denied approval", async () => {
    const gw = await h.startGateway();
    const { approvalId } = await h.createApproval(gw.base, agent, DELETE, { id: 1 });
    expect((await h.denyVia(gw.base, admin, approvalId)).status).toBe(200);
    const res = await h.mcp(
      gw.base,
      agent,
      DELETE,
      { id: 1 },
      { "x-aegis-approval-id": approvalId },
    );
    expect(((await res.json()) as { error?: { code: number } }).error?.code).toBe(-32002);
    expect(h.connections).toBe(0);
    await gw.close();
  });

  it("cannot approve an already-approved approval", async () => {
    const gw = await h.startGateway();
    const { approvalId } = await h.createApproval(gw.base, agent, DELETE, { id: 1 });
    expect((await h.approveVia(gw.base, admin, approvalId)).status).toBe(200);
    expect((await h.approveVia(gw.base, admin, approvalId)).status).toBe(409);
    await gw.close();
    expect((await h.approvalRow(approvalId))?.status).toBe("APPROVED");
  });

  it("cannot approve an already-denied approval", async () => {
    const gw = await h.startGateway();
    const { approvalId } = await h.createApproval(gw.base, agent, DELETE, { id: 1 });
    expect((await h.denyVia(gw.base, admin, approvalId)).status).toBe(200);
    expect((await h.approveVia(gw.base, admin, approvalId)).status).toBe(409);
    await gw.close();
  });

  it("cannot approve an expired approval", async () => {
    const gw = await h.startGateway();
    const { approvalId } = await h.createApproval(gw.base, agent, DELETE, { id: 1 });
    await h.pool.query(
      "UPDATE approvals SET expires_at = now() - interval '1 minute' WHERE id = $1",
      [approvalId],
    );
    expect((await h.approveVia(gw.base, admin, approvalId)).status).toBe(409);
    await gw.close();
    expect((await h.approvalRow(approvalId))?.status).toBe("EXPIRED");
  });

  it("never executes an expired (approved) approval", async () => {
    const gw = await h.startGateway();
    const { approvalId } = await h.createApproval(gw.base, agent, DELETE, { id: 1 });
    await h.approveVia(gw.base, admin, approvalId);
    await h.pool.query(
      "UPDATE approvals SET expires_at = now() - interval '1 minute' WHERE id = $1",
      [approvalId],
    );
    const res = await h.mcp(
      gw.base,
      agent,
      DELETE,
      { id: 1 },
      { "x-aegis-approval-id": approvalId },
    );
    expect(((await res.json()) as { error?: { code: number } }).error?.code).toBe(-32002);
    expect(h.connections).toBe(0);
    await gw.close();
    expect((await h.approvalRow(approvalId))?.consumed_at).toBeNull();
  });

  it("refuses an approval used by a different agent", async () => {
    const gw = await h.startGateway();
    const { approvalId } = await h.createApproval(gw.base, agent, DELETE, { id: 1 });
    await h.approveVia(gw.base, admin, approvalId);
    const res = await h.mcp(
      gw.base,
      otherAgent,
      DELETE,
      { id: 1 },
      { "x-aegis-approval-id": approvalId },
    );
    expect(((await res.json()) as { error?: { code: number } }).error?.code).toBe(-32002);
    expect(h.connections).toBe(0);
    await gw.close();
  });

  it("refuses an approval used against a different server", async () => {
    const gwA = await h.startGateway();
    const { approvalId } = await h.createApproval(gwA.base, agent, DELETE, { id: 1 });
    await h.approveVia(gwA.base, admin, approvalId);

    // Second gateway with a different server identity, same database.
    const gwB = await h.startGateway({
      serverId: `${PREFIX}server-b`,
      serverName: `${PREFIX}server-b`,
    });
    const res = await h.mcp(
      gwB.base,
      agent,
      DELETE,
      { id: 1 },
      { "x-aegis-approval-id": approvalId },
    );
    expect(((await res.json()) as { error?: { code: number } }).error?.code).toBe(-32002);
    expect(h.connections).toBe(0);

    await gwA.close();
    await gwB.close();
  });

  it("refuses an approval used for a different tool", async () => {
    const gw = await h.startGateway();
    const { approvalId } = await h.createApproval(gw.base, agent, DELETE, { id: 1 });
    await h.approveVia(gw.base, admin, approvalId);
    const res = await h.mcp(
      gw.base,
      agent,
      OTHER,
      { id: 1 },
      { "x-aegis-approval-id": approvalId },
    );
    expect(((await res.json()) as { error?: { code: number } }).error?.code).toBe(-32002);
    expect(h.connections).toBe(0);
    await gw.close();
  });

  it("refuses an approval used for a different method", async () => {
    const gw = await h.startGateway();
    // Approval bound to tools/list (no tool name, no arguments).
    const listRes = await h.mcp(gw.base, agent, "", {}, {}, "list-1", "tools/list");
    const listBody = (await listRes.json()) as {
      error?: { code: number; data?: { approvalId?: string } };
    };
    expect(listBody.error?.code).toBe(-32002);
    const approvalId = listBody.error?.data?.approvalId;
    if (approvalId === undefined) throw new Error("no approval id");
    await h.approveVia(gw.base, admin, approvalId);

    // Attempt to use it for a tools/call.
    const res = await h.mcp(
      gw.base,
      agent,
      DELETE,
      { id: 1 },
      { "x-aegis-approval-id": approvalId },
    );
    expect(((await res.json()) as { error?: { code: number } }).error?.code).toBe(-32002);
    expect(h.connections).toBe(0);
    await gw.close();
  });

  it("refuses an approval whose arguments changed", async () => {
    const gw = await h.startGateway();
    const { approvalId } = await h.createApproval(gw.base, agent, DELETE, { id: 1, name: "a" });
    await h.approveVia(gw.base, admin, approvalId);
    const res = await h.mcp(
      gw.base,
      agent,
      DELETE,
      { id: 1, name: "b" },
      { "x-aegis-approval-id": approvalId },
    );
    expect(((await res.json()) as { error?: { code: number } }).error?.code).toBe(-32002);
    expect(h.connections).toBe(0);
    await gw.close();
  });

  it("accepts semantically equal arguments in a different key order (canonical binding)", async () => {
    const gw = await h.startGateway();
    const { approvalId } = await h.createApproval(gw.base, agent, DELETE, { a: 1, b: 2 });
    await h.approveVia(gw.base, admin, approvalId);
    const res = await h.mcp(
      gw.base,
      agent,
      DELETE,
      { b: 2, a: 1 },
      { "x-aegis-approval-id": approvalId },
    );
    expect(res.status).toBe(200);
    expect((await res.json()).result).toBeDefined();
    expect(h.connections).toBe(1);
    await gw.close();
  });

  it('refuses argument representation confusion ("1" vs 1)', async () => {
    const gw = await h.startGateway();
    const { approvalId } = await h.createApproval(gw.base, agent, DELETE, { n: "1" });
    await h.approveVia(gw.base, admin, approvalId);
    const res = await h.mcp(
      gw.base,
      agent,
      DELETE,
      { n: 1 },
      { "x-aegis-approval-id": approvalId },
    );
    expect(((await res.json()) as { error?: { code: number } }).error?.code).toBe(-32002);
    expect(h.connections).toBe(0);
    await gw.close();
  });

  it("refuses an approval reused for a different request (unknown id)", async () => {
    const gw = await h.startGateway();
    const res = await h.mcp(
      gw.base,
      agent,
      DELETE,
      { id: 1 },
      { "x-aegis-approval-id": "apr_does_not_exist" },
    );
    expect(((await res.json()) as { error?: { code: number } }).error?.code).toBe(-32002);
    expect(h.connections).toBe(0);
    await gw.close();
  });

  it("allows exactly one execution under concurrent consumption of one approval", async () => {
    const gw = await h.startGateway();
    const { approvalId } = await h.createApproval(gw.base, agent, DELETE, { id: 42 });
    await h.approveVia(gw.base, admin, approvalId);

    const attempts = await Promise.all(
      Array.from({ length: 8 }, (_, index) =>
        h.mcp(
          gw.base,
          agent,
          DELETE,
          { id: 42 },
          { "x-aegis-approval-id": approvalId },
          `race-${index}`,
        ),
      ),
    );
    const bodies = await Promise.all(
      attempts.map((r) => r.json() as Promise<{ result?: unknown }>),
    );
    const successes = bodies.filter((b) => b.result !== undefined).length;

    expect(successes).toBe(1);
    expect(h.connections).toBe(1);

    await gw.close();
    const row = await h.approvalRow(approvalId);
    expect(row?.status).toBe("APPROVED");
    expect(row?.consumed_at).not.toBeNull();
  });
});
