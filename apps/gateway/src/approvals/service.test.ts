import { describe, it, expect, beforeEach } from "vitest";
import { ApprovalService } from "./service.js";
import { InMemoryApprovalRepository } from "../repositories/memory.js";
import type { SecurityContext } from "../mcp/types.js";
import type { PolicyEvaluation } from "../policy/types.js";
import type { AuditEvent, AuditSink, AuditSinkStats } from "../audit/types.js";

class RecordingSink implements AuditSink {
  readonly events: AuditEvent[] = [];
  record(event: AuditEvent): void {
    this.events.push(event);
  }
  async flush(): Promise<void> {}
  async close(): Promise<void> {}
  stats(): AuditSinkStats {
    return { queued: 0, flushed: this.events.length, failed: 0, dropped: 0 };
  }
}

const evaluation: PolicyEvaluation = {
  decision: "REQUIRE_APPROVAL",
  policyId: "approval-policy",
  reason: "destructive action requires approval",
};

function context(overrides: Partial<SecurityContext> = {}): SecurityContext {
  return {
    requestId: 1,
    protocolVersion: undefined,
    method: "tools/call",
    toolName: "database.delete",
    toolArguments: { id: 1, password: "hunter2" },
    agent: { id: "agent-1", name: "Agent One" },
    server: { id: "server-1", name: "Server", upstreamUrl: "http://upstream.invalid/mcp" },
    timestamp: 1_000,
    ...overrides,
  };
}

describe("ApprovalService", () => {
  let repo: InMemoryApprovalRepository;
  let sink: RecordingSink;
  let now: number;
  let ids: number;

  beforeEach(() => {
    repo = new InMemoryApprovalRepository();
    sink = new RecordingSink();
    now = 10_000;
    ids = 0;
  });

  function service(): ApprovalService {
    return new ApprovalService(repo, sink, {
      now: () => now,
      idFactory: () => `apr_test_${++ids}`,
      defaultTtlMs: 1_000,
      maxTtlMs: 5_000,
    });
  }

  it("creates a PENDING approval and audits it", async () => {
    const created = await service().createForContext(context(), evaluation);
    expect(created.kind).toBe("created");
    if (created.kind !== "created") return;

    expect(created.approval.status).toBe("PENDING");
    expect(created.approval.expiresAt).toBe(11_000);
    expect(created.approval.approverId).toBeNull();
    expect(sink.events.map((event) => event.eventType)).toEqual(["approval_created"]);
    expect(sink.events[0]?.outcome).toBe("pending");
    expect(sink.events[0]?.approvalId).toBe(created.approval.id);
  });

  it("redacts sensitive arguments before persisting them", async () => {
    const created = await service().createForContext(context(), evaluation);
    if (created.kind !== "created") throw new Error("expected creation");
    expect(created.approval.arguments).toEqual({ id: 1, password: "[REDACTED]" });
    expect(JSON.stringify(created.approval)).not.toContain("hunter2");
  });

  it("reuses an existing PENDING approval for the same binding", async () => {
    const svc = service();
    const first = await svc.createForContext(context(), evaluation);
    const second = await svc.createForContext(context(), evaluation);
    if (first.kind !== "created" || second.kind !== "existing") throw new Error("bad kinds");
    expect(second.approval.id).toBe(first.approval.id);
    // Only one creation is audited.
    expect(sink.events).toHaveLength(1);
  });

  it("creates a distinct approval when arguments differ", async () => {
    const svc = service();
    const first = await svc.createForContext(context(), evaluation);
    const second = await svc.createForContext(context({ toolArguments: { id: 2 } }), evaluation);
    if (first.kind !== "created" || second.kind !== "created") throw new Error("bad kinds");
    expect(second.approval.id).not.toBe(first.approval.id);
  });

  it("fails closed (unavailable) without a repository", async () => {
    const svc = new ApprovalService(null, sink);
    expect((await svc.createForContext(context(), evaluation)).kind).toBe("unavailable");
  });

  it("approves a PENDING approval and audits the decision", async () => {
    const svc = service();
    const created = await svc.createForContext(context(), evaluation);
    if (created.kind !== "created") throw new Error("expected creation");

    const result = await svc.approve(created.approval.id, "admin-1", "looks fine");
    expect(result.kind).toBe("approved");
    if (result.kind !== "approved") return;
    expect(result.approval.status).toBe("APPROVED");
    expect(result.approval.approverId).toBe("admin-1");
    expect(result.approval.decisionReason).toBe("looks fine");
    expect(sink.events.map((event) => event.eventType)).toContain("approval_approved");
  });

  it("denies a PENDING approval and audits the decision", async () => {
    const svc = service();
    const created = await svc.createForContext(context(), evaluation);
    if (created.kind !== "created") throw new Error("expected creation");

    const result = await svc.deny(created.approval.id, "admin-1", "too risky");
    expect(result.kind).toBe("denied");
    expect(sink.events.map((event) => event.eventType)).toContain("approval_denied");
  });

  it("does not allow approving an already-decided approval", async () => {
    const svc = service();
    const created = await svc.createForContext(context(), evaluation);
    if (created.kind !== "created") throw new Error("expected creation");
    await svc.approve(created.approval.id, "admin-1");

    const again = await svc.approve(created.approval.id, "admin-2");
    expect(again.kind).toBe("already_decided");
  });

  it("does not allow approving an expired approval and marks it EXPIRED", async () => {
    const svc = service();
    const created = await svc.createForContext(context(), evaluation);
    if (created.kind !== "created") throw new Error("expected creation");

    now = 20_000; // past expiresAt
    const result = await svc.approve(created.approval.id, "admin-1");
    expect(result.kind).toBe("expired");
    expect((await svc.getById(created.approval.id))?.status).toBe("EXPIRED");
    expect(sink.events.map((event) => event.eventType)).toContain("approval_expired");
  });

  it("never consumes a PENDING approval (pending never executes)", async () => {
    const svc = service();
    const created = await svc.createForContext(context(), evaluation);
    if (created.kind !== "created") throw new Error("expected creation");

    const consumed = await svc.consume(created.approval.id, context(), "agent-1");
    expect(consumed.kind).toBe("not_approved");
  });

  it("never consumes a DENIED approval", async () => {
    const svc = service();
    const created = await svc.createForContext(context(), evaluation);
    if (created.kind !== "created") throw new Error("expected creation");
    await svc.deny(created.approval.id, "admin-1");

    const consumed = await svc.consume(created.approval.id, context(), "agent-1");
    expect(consumed.kind).toBe("not_approved");
  });

  it("consumes an APPROVED approval bound to the exact request, exactly once", async () => {
    const svc = service();
    const created = await svc.createForContext(context(), evaluation);
    if (created.kind !== "created") throw new Error("expected creation");
    await svc.approve(created.approval.id, "admin-1");

    const first = await svc.consume(created.approval.id, context(), "agent-1");
    expect(first.kind).toBe("ok");
    if (first.kind === "ok") expect(first.approval.consumedAt).toBe(10_000);

    // Replay is refused.
    const replay = await svc.consume(created.approval.id, context(), "agent-1");
    expect(replay.kind).toBe("already_consumed");
  });

  it("refuses an approval bound to a different agent", async () => {
    const svc = service();
    const created = await svc.createForContext(context(), evaluation);
    if (created.kind !== "created") throw new Error("expected creation");
    await svc.approve(created.approval.id, "admin-1");

    const consumed = await svc.consume(
      created.approval.id,
      context({ agent: { id: "agent-2", name: "Other" } }),
      "agent-2",
    );
    expect(consumed.kind).toBe("binding_mismatch");
  });

  it("refuses an approval bound to a different server", async () => {
    const svc = service();
    const created = await svc.createForContext(context(), evaluation);
    if (created.kind !== "created") throw new Error("expected creation");
    await svc.approve(created.approval.id, "admin-1");

    const consumed = await svc.consume(
      created.approval.id,
      context({ server: { id: "server-2", name: "Other", upstreamUrl: "http://x/mcp" } }),
      "agent-1",
    );
    expect(consumed.kind).toBe("binding_mismatch");
  });

  it("refuses an approval bound to different arguments (wrong request)", async () => {
    const svc = service();
    const created = await svc.createForContext(context(), evaluation);
    if (created.kind !== "created") throw new Error("expected creation");
    await svc.approve(created.approval.id, "admin-1");

    const consumed = await svc.consume(
      created.approval.id,
      context({ toolArguments: { id: 999 } }),
      "agent-1",
    );
    expect(consumed.kind).toBe("binding_mismatch");
  });

  it("never consumes an APPROVED approval past its expiry", async () => {
    const svc = service();
    const created = await svc.createForContext(context(), evaluation);
    if (created.kind !== "created") throw new Error("expected creation");
    await svc.approve(created.approval.id, "admin-1");

    now = 20_000;
    const consumed = await svc.consume(created.approval.id, context(), "agent-1");
    expect(consumed.kind).toBe("expired");
    expect((await svc.getById(created.approval.id))?.consumedAt).toBeNull();
  });

  it("expires stale PENDING approvals and audits each", async () => {
    const svc = service();
    const created = await svc.createForContext(context(), evaluation);
    if (created.kind !== "created") throw new Error("expected creation");

    now = 20_000;
    const expired = await svc.expireStale();
    expect(expired).toHaveLength(1);
    expect(expired[0]?.status).toBe("EXPIRED");
    expect(sink.events.filter((event) => event.eventType === "approval_expired")).toHaveLength(1);
  });

  it("does not approve an unknown approval id", async () => {
    const result = await service().approve("apr_missing", "admin-1");
    expect(result.kind).toBe("not_found");
  });

  it("clamps the TTL to the configured maximum", async () => {
    const created = await service().createForContext(context(), evaluation, 999_999);
    if (created.kind !== "created") throw new Error("expected creation");
    expect(created.approval.expiresAt - created.approval.createdAt).toBe(5_000);
  });
});
