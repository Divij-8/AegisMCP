import { describe, it, expect } from "vitest";
import { RiskEngine } from "./engine.js";
import type { SecurityContext } from "../mcp/types.js";
import type { PolicyEvaluation } from "../policy/types.js";

function context(toolName: string | undefined, method = "tools/call"): SecurityContext {
  return {
    requestId: 1,
    protocolVersion: undefined,
    method,
    toolName,
    toolArguments: {},
    agent: { id: "agent-1", name: "Agent One" },
    server: { id: "server-1", name: "Server", upstreamUrl: "http://upstream.invalid/mcp" },
    timestamp: 0,
  };
}

function evaluation(decision: PolicyEvaluation["decision"]): PolicyEvaluation {
  return { decision, policyId: "p", reason: "policy reason" };
}

describe("RiskEngine.assess", () => {
  const engine = new RiskEngine();

  it("reports LOW with no findings for a benign tool", () => {
    const assessment = engine.assess(context("echo"));
    expect(assessment.level).toBe("LOW");
    expect(assessment.findings).toHaveLength(0);
    expect(assessment.enhancedAudit).toBe(false);
  });

  it("flags destructive tools as HIGH", () => {
    const assessment = engine.assess(context("database.delete"));
    expect(assessment.level).toBe("HIGH");
    expect(assessment.findings.some((f) => f.signal === "destructive-operation")).toBe(true);
  });

  it("flags shell execution as CRITICAL", () => {
    expect(engine.assess(context("run_shell")).level).toBe("CRITICAL");
  });

  it("flags external side effects as MEDIUM and requests enhanced audit", () => {
    const assessment = engine.assess(context("send_email"));
    expect(assessment.level).toBe("MEDIUM");
    expect(assessment.enhancedAudit).toBe(true);
  });

  it("is deterministic", () => {
    const first = engine.assess(context("database.delete"));
    const second = engine.assess(context("database.delete"));
    expect(first).toEqual(second);
  });
});

describe("RiskEngine.apply", () => {
  const engine = new RiskEngine();

  it("does not weaken an explicit DENY", () => {
    const result = engine.apply(context("echo"), evaluation("DENY"));
    expect(result.evaluation.decision).toBe("DENY");
  });

  it("keeps DENY even under CRITICAL risk", () => {
    const result = engine.apply(context("run_shell"), evaluation("DENY"));
    expect(result.evaluation.decision).toBe("DENY");
  });

  it("escalates ALLOW to REQUIRE_APPROVAL for HIGH risk", () => {
    const result = engine.apply(context("database.delete"), evaluation("ALLOW"));
    expect(result.evaluation.decision).toBe("REQUIRE_APPROVAL");
    expect(result.assessment.level).toBe("HIGH");
  });

  it("escalates ALLOW to DENY for CRITICAL risk", () => {
    const result = engine.apply(context("run_shell"), evaluation("ALLOW"));
    expect(result.evaluation.decision).toBe("DENY");
  });

  it("never downgrades REQUIRE_APPROVAL to ALLOW", () => {
    const result = engine.apply(context("echo"), evaluation("REQUIRE_APPROVAL"));
    expect(result.evaluation.decision).toBe("REQUIRE_APPROVAL");
  });

  it("passes through ALLOW for LOW risk without changing the reason", () => {
    const result = engine.apply(context("echo"), evaluation("ALLOW"));
    expect(result.evaluation).toEqual(evaluation("ALLOW"));
  });

  it("preserves the policy id when escalating", () => {
    const result = engine.apply(context("database.delete"), evaluation("ALLOW"));
    expect(result.evaluation.policyId).toBe("p");
  });

  it("honors a custom mapping", () => {
    const custom = new RiskEngine({
      mapping: { LOW: "REQUIRE_APPROVAL", MEDIUM: "INHERIT", HIGH: "INHERIT", CRITICAL: "INHERIT" },
    });
    const result = custom.apply(context("echo"), evaluation("ALLOW"));
    expect(result.evaluation.decision).toBe("REQUIRE_APPROVAL");
  });

  it("honors a custom baseline", () => {
    const custom = new RiskEngine({ baseline: "HIGH" });
    const result = custom.apply(context("echo"), evaluation("ALLOW"));
    expect(result.evaluation.decision).toBe("REQUIRE_APPROVAL");
  });
});
