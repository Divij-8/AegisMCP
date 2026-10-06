import { describe, it, expect, beforeEach } from "vitest";
import { runOperationsCli } from "./cli.js";
import type { CliIo, OperationsCliDeps } from "./cli.js";
import { buildInMemoryRepositories } from "../repositories/memory.js";
import { ApprovalService } from "../approvals/service.js";
import { NullAuditSink } from "../audit/null-sink.js";
import type { Repositories } from "../repositories/types.js";
import type { SecurityContext } from "../mcp/types.js";
import type { PolicyEvaluation } from "../policy/types.js";

class Capture implements CliIo {
  readonly lines: string[] = [];
  readonly errors: string[] = [];
  out(line: string): void {
    this.lines.push(line);
  }
  err(line: string): void {
    this.errors.push(line);
  }
}

const evaluation: PolicyEvaluation = {
  decision: "REQUIRE_APPROVAL",
  policyId: "p",
  reason: "needs approval",
};

function context(agentId: string): SecurityContext {
  return {
    requestId: 1,
    protocolVersion: undefined,
    method: "tools/call",
    toolName: "danger.delete",
    toolArguments: { id: 1 },
    agent: { id: agentId, name: agentId },
    server: { id: "s", name: "s", upstreamUrl: "http://u/mcp" },
    timestamp: 0,
  };
}

describe("operations CLI", () => {
  let repositories: Repositories;
  let approvals: ApprovalService;
  let io: Capture;
  let deps: OperationsCliDeps;

  beforeEach(async () => {
    repositories = buildInMemoryRepositories();
    approvals = new ApprovalService(repositories.approvals, new NullAuditSink());
    io = new Capture();
    deps = { repositories, approvals, actorId: "cli-operator" };
  });

  it("prints usage with no arguments", async () => {
    expect(await runOperationsCli([], io, deps)).toBe(0);
    expect(io.lines.join("\n")).toContain("operations CLI");
  });

  it("creates an agent with a role", async () => {
    const code = await runOperationsCli(
      ["agent", "create", "--id", "admin-1", "--role", "ADMIN"],
      io,
      deps,
    );
    expect(code).toBe(0);
    expect(await repositories.agents.findById("admin-1")).toEqual({
      id: "admin-1",
      name: "admin-1",
      role: "ADMIN",
    });
  });

  it("tolerates the `--` delimiter a package manager forwards", async () => {
    const code = await runOperationsCli(
      ["--", "agent", "create", "--id", "ops-1", "--role", "OPERATOR"],
      io,
      deps,
    );
    expect(code).toBe(0);
    expect(await repositories.agents.findById("ops-1")).toEqual({
      id: "ops-1",
      name: "ops-1",
      role: "OPERATOR",
    });
  });

  it("rejects an invalid role", async () => {
    const code = await runOperationsCli(
      ["agent", "create", "--id", "x", "--role", "SUPERUSER"],
      io,
      deps,
    );
    expect(code).toBe(1);
    expect(io.errors.join("\n")).toContain("role must be");
  });

  it("revokes all credentials of an agent", async () => {
    await repositories.agents.upsert({ id: "a", name: "a" });
    await repositories.credentials.create({
      keyId: "k1",
      agent: { id: "a", name: "a" },
      secretHash: "h",
      salt: "s",
      hashAlgo: "scrypt-v1",
      createdAt: 1,
      expiresAt: null,
    });

    const code = await runOperationsCli(["agent", "revoke", "--id", "a"], io, deps);
    expect(code).toBe(0);
    expect((await repositories.credentials.findByKeyId("k1"))?.revokedAt).not.toBeNull();
  });

  it("creates a valid policy", async () => {
    const code = await runOperationsCli(
      [
        "policy",
        "create",
        "--id",
        "p1",
        "--decision",
        "REQUIRE_APPROVAL",
        "--reason",
        "risky",
        "--tool",
        "danger.delete",
      ],
      io,
      deps,
    );
    expect(code).toBe(0);
    expect(await repositories.policies.findById("p1")).toMatchObject({
      id: "p1",
      decision: "REQUIRE_APPROVAL",
      match: { tool: "danger.delete" },
    });
  });

  it("rejects an invalid policy decision without writing", async () => {
    const code = await runOperationsCli(
      ["policy", "create", "--id", "p1", "--decision", "MAYBE", "--reason", "x"],
      io,
      deps,
    );
    expect(code).toBe(1);
    expect(await repositories.policies.listAll({ limit: 10, offset: 0 })).toMatchObject({
      total: 0,
    });
  });

  it("rejects a misspelled match flag instead of storing a catch-all policy", async () => {
    const code = await runOperationsCli(
      [
        "policy",
        "create",
        "--id",
        "p-typo",
        "--decision",
        "ALLOW",
        "--reason",
        "typo",
        "--toool",
        "echo",
      ],
      io,
      deps,
    );

    expect(code).toBe(1);
    expect(io.errors.join("\n")).toContain('Unknown flag "--toool"');
    // The silent-drop behavior would have stored match={} — a policy allowing
    // every tool. Nothing may be written.
    expect(await repositories.policies.listAll({ limit: 10, offset: 0 })).toMatchObject({
      total: 0,
    });
  });

  it("rejects any flag on a command that accepts none", async () => {
    const code = await runOperationsCli(["agent", "list", "--role", "ADMIN"], io, deps);

    expect(code).toBe(1);
    expect(io.errors.join("\n")).toContain('Unknown flag "--role"');
    expect(io.errors.join("\n")).toContain("accepts no flags");
  });

  it("lists an empty approval queue", async () => {
    expect(await runOperationsCli(["approval", "list"], io, deps)).toBe(0);
    expect(io.lines.join("\n")).toContain("No approvals");
  });

  it("approves a pending approval", async () => {
    const created = await approvals.createForContext(context("a"), evaluation);
    if (created.kind !== "created") throw new Error("expected creation");

    const code = await runOperationsCli(
      ["approval", "approve", "--id", created.approval.id, "--reason", "ok"],
      io,
      deps,
    );
    expect(code).toBe(0);
    expect((await approvals.getById(created.approval.id))?.status).toBe("APPROVED");
  });

  it("denies a pending approval", async () => {
    const created = await approvals.createForContext(context("a"), evaluation);
    if (created.kind !== "created") throw new Error("expected creation");

    const code = await runOperationsCli(
      ["approval", "deny", "--id", created.approval.id],
      io,
      deps,
    );
    expect(code).toBe(0);
    expect((await approvals.getById(created.approval.id))?.status).toBe("DENIED");
  });

  it("fails on an unknown approval id", async () => {
    const code = await runOperationsCli(["approval", "approve", "--id", "nope"], io, deps);
    expect(code).toBe(1);
  });

  it("lists audit events", async () => {
    const code = await runOperationsCli(["audit", "list"], io, deps);
    expect(code).toBe(0);
    expect(io.lines.join("\n")).toContain("No audit events");
  });
});
