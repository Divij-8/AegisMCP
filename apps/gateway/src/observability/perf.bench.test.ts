/**
 * Performance baseline — micro-benchmarks of the hot-path building blocks.
 *
 * These are intentionally simple: average microseconds per operation, with
 * generous upper bounds so the suite catches pathological regressions (e.g. an
 * accidental O(n^2) or synchronous IO on the request path) without being flaky
 * on shared CI runners. Numbers are printed for the engineering record.
 */

import { describe, it, expect } from "vitest";
import { PolicyEngine } from "../policy/engine.js";
import { RiskEngine } from "../risk/engine.js";
import { hashArguments } from "../approvals/redact.js";
import { BufferedAuditSink } from "../audit/sink.js";
import {
  InMemoryApprovalRepository,
  InMemoryAuditEventRepository,
} from "../repositories/memory.js";
import { ApprovalService } from "../approvals/service.js";
import { NullAuditSink } from "../audit/null-sink.js";
import type { SecurityContext } from "../mcp/types.js";
import type { Policy } from "../policy/types.js";
import type { AuditEvent } from "../audit/types.js";

const results: Array<{ name: string; usPerOp: number }> = [];

function record(name: string, usPerOp: number): void {
  results.push({ name, usPerOp });
}

function bench(iterations: number, fn: () => void): number {
  const start = performance.now();
  for (let i = 0; i < iterations; i++) fn();
  const elapsedMs = performance.now() - start;
  return (elapsedMs * 1000) / iterations;
}

function context(toolName: string, args: Record<string, unknown> = {}): SecurityContext {
  return {
    requestId: 1,
    protocolVersion: "2026-07-28",
    method: "tools/call",
    toolName,
    toolArguments: args,
    agent: { id: "bench-agent", name: "bench-agent" },
    server: { id: "bench-server", name: "bench-server", upstreamUrl: "http://127.0.0.1:1/mcp" },
    timestamp: 0,
  };
}

const auditEvent: AuditEvent = {
  eventType: "request",
  requestId: 1,
  occurredAt: 0,
  agentId: "bench-agent",
  serverId: "bench-server",
  method: "tools/call",
  toolName: "echo",
  decision: "ALLOW",
  policyId: "p",
  reason: "bench",
  outcome: "forwarded",
  upstreamStatus: 200,
  latencyMs: 1,
};

describe("performance baseline (micro-benchmarks)", () => {
  it("policy evaluation stays well under 2ms per evaluation", () => {
    const policies: Policy[] = Array.from({ length: 25 }, (_, i) => ({
      id: `p${i}`,
      decision: i % 3 === 0 ? "DENY" : "ALLOW",
      match: { tool: `tool-${i}` },
      reason: "bench",
      priority: i,
    }));
    const engine = new PolicyEngine(policies);
    const ctx = context("tool-12");
    const us = bench(5000, () => engine.evaluate(ctx));
    record("policy.evaluate", us);
    expect(us).toBeLessThan(2000);
  });

  it("risk evaluation stays well under 2ms per request", () => {
    const engine = new RiskEngine();
    const ctx = context("database.delete");
    const us = bench(5000, () =>
      engine.apply(ctx, { decision: "ALLOW", policyId: "p", reason: "r" }),
    );
    record("risk.apply", us);
    expect(us).toBeLessThan(2000);
  });

  it("argument hashing for approval binding stays well under 2ms", () => {
    const args = { id: 1, nested: { a: "x", b: [1, 2, 3] }, name: "resource" };
    const us = bench(5000, () => hashArguments(args));
    record("approval.hashArguments", us);
    expect(us).toBeLessThan(2000);
  });

  it("audit enqueue is non-blocking and well under 2ms", () => {
    const sink = new BufferedAuditSink(new InMemoryAuditEventRepository(), {
      flushIntervalMs: 60_000,
    });
    const us = bench(5000, () => sink.record(auditEvent));
    record("audit.record (enqueue)", us);
    void sink.close();
    expect(us).toBeLessThan(2000);
  });

  it("approval creation (in-memory) stays well under 5ms", async () => {
    const repo = new InMemoryApprovalRepository();
    const service = new ApprovalService(repo, new NullAuditSink());
    const start = performance.now();
    const iterations = 500;
    for (let i = 0; i < iterations; i++) {
      await service.createForContext(context(`delete_${i}`, { id: i }), {
        decision: "REQUIRE_APPROVAL",
        policyId: "p",
        reason: "bench",
      });
    }
    const us = ((performance.now() - start) * 1000) / iterations;
    record("approval.create", us);
    expect(us).toBeLessThan(5000);
  });

  it("prints the collected baseline", () => {
    const lines = results.map((r) => `  ${r.name.padEnd(30)} ${r.usPerOp.toFixed(2)} µs/op`);
    console.log("\nPerformance baseline (avg per op):\n" + lines.join("\n") + "\n");
    expect(results.length).toBeGreaterThanOrEqual(5);
  });
});
