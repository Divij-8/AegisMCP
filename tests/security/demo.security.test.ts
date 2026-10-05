import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { SecurityHarness, hasDb } from "./helpers.js";

const d = describe.skipIf(!hasDb);

const PREFIX = "sec-demo-";
const DANGEROUS_TOOL = "delete_resource";
const policies = [
  {
    id: `${PREFIX}require`,
    decision: "REQUIRE_APPROVAL" as const,
    match: { tool: DANGEROUS_TOOL },
    reason: "destructive tool requires approval",
  },
];

/**
 * Reproducible end-to-end security demo.
 *
 * A realistic dangerous action (an agent trying to delete a production
 * resource) is intercepted, held for human approval, executed exactly once,
 * and recorded end-to-end. Every guarantee in the README's "Security
 * Guarantees" section is exercised here.
 */
d("DEMO: agent → auth → policy → risk → approval → execution → audit", () => {
  const h = new SecurityHarness(PREFIX, policies);

  beforeAll(() => h.setup());
  afterAll(() => h.teardown());
  beforeEach(() => h.clean());

  it("blocks, requires approval, executes once after approval, and records the lifecycle", async () => {
    // 1. Provision a known agent and an administrator.
    const agentId = `${PREFIX}agent`;
    const agent = await h.provision(agentId);
    const admin = await h.provision(`${PREFIX}admin`, "ADMIN");
    const gw = await h.startGateway();

    // 2. Agent attempts a dangerous tool, authenticated with its credential.
    const args = { resource: "prod-database", force: true, password: "P@ssw0rd" };
    const attempt = await h.mcp(gw.base, agent, DANGEROUS_TOOL, args, {}, "demo-1");

    // 3–8. Policy required approval; a PENDING approval exists; upstream untouched.
    expect(attempt.status).toBe(200);
    const attemptBody = (await attempt.json()) as {
      error?: {
        code: number;
        message: string;
        data?: { approvalId?: string; status?: string; expiresAt?: number };
      };
    };
    expect(attemptBody.error?.code).toBe(-32002);
    expect(attemptBody.error?.data?.status).toBe("PENDING");
    expect(attemptBody.error?.data?.expiresAt).toBeGreaterThan(Date.now());
    const approvalId = attemptBody.error?.data?.approvalId as string;
    expect(approvalId).toMatch(/^apr_[0-9a-f]{32}$/);
    expect(h.connections).toBe(0); // tool NOT executed

    // Approval record: bound to the agent, redacted, expiring, unconsumed.
    const row = await h.approvalRow(approvalId);
    expect(row?.status).toBe("PENDING");
    expect(row?.agent_id).toBe(agentId);
    expect(row?.method).toBe("tools/call");
    expect(row?.tool_name).toBe(DANGEROUS_TOOL);
    expect(row?.consumed_at).toBeNull();
    expect(JSON.stringify(row?.arguments)).not.toContain("P@ssw0rd");
    expect((row?.arguments as Record<string, unknown>).password).toBe("[REDACTED]");

    // 9. Administrator sees the pending approval and its justification.
    const queue = await h.admin(gw.base, admin, "/approvals?status=PENDING");
    const queueBody = (await queue.json()) as { items: { id: string }[] };
    expect(queueBody.items.some((item) => item.id === approvalId)).toBe(true);
    const detail = (await (await h.admin(gw.base, admin, `/approvals/${approvalId}`)).json()) as {
      reason: string;
      policyId: string;
    };
    expect(detail.policyId).toBe(`${PREFIX}require`);
    expect(detail.reason).toContain("requires approval");

    // 10. Administrator approves.
    const approved = await h.approveVia(gw.base, admin, approvalId, "reviewed for prod");
    expect(approved.status).toBe(200);

    // 11. Agent retries with the approval id; binding is verified and it executes.
    const executed = await h.mcp(
      gw.base,
      agent,
      DANGEROUS_TOOL,
      args,
      { "x-aegis-approval-id": approvalId },
      "demo-2",
    );
    expect(executed.status).toBe(200);
    expect((await executed.json()).result).toBeDefined();
    expect(h.connections).toBe(1);

    // 12–13. Approval consumed atomically.
    const consumed = await h.approvalRow(approvalId);
    expect(consumed?.status).toBe("APPROVED");
    expect(consumed?.consumed_at).not.toBeNull();

    // 14. Replay fails and does not execute again.
    const replay = await h.mcp(
      gw.base,
      agent,
      DANGEROUS_TOOL,
      args,
      { "x-aegis-approval-id": approvalId },
      "demo-3",
    );
    expect(((await replay.json()) as { error?: { code: number } }).error?.code).toBe(-32002);
    expect(h.connections).toBe(1);

    await gw.close();

    // 15. Audit records the complete lifecycle with identity, decision, and risk.
    const audit = await h.auditRowsFor(approvalId);
    const types = audit.map((r) => r.event_type);
    expect(types).toContain("approval_created");
    expect(types).toContain("approval_approved");

    const requestEvents = audit.filter((r) => r.event_type === "request");
    expect(requestEvents.length).toBeGreaterThanOrEqual(2);
    for (const event of requestEvents) {
      expect(event.agent_id).toBe(agentId);
      expect(event.decision).toBe("REQUIRE_APPROVAL");
      expect(event.risk_level).toBe("HIGH"); // delete_resource is destructive
    }
    expect(requestEvents.some((r) => r.outcome === "blocked")).toBe(true);
    expect(requestEvents.some((r) => r.outcome === "forwarded")).toBe(true);

    // No secrets anywhere in the lifecycle audit rows.
    expect(JSON.stringify(audit)).not.toContain("P@ssw0rd");
  });
});
