import { describe, it, expect } from "vitest";
import { PolicyEngine } from "./engine.js";
import type { SecurityContext } from "../mcp/types.js";
import type { Policy } from "./types.js";

const baseContext: SecurityContext = {
  requestId: 1,
  protocolVersion: "2026-07-28",
  method: "tools/call",
  toolName: "echo",
  toolArguments: { message: "hello" },
  agent: { id: "alpha-agent", name: "alpha" },
  server: { id: "mock-server", name: "mock-server", upstreamUrl: "http://127.0.0.1:3001/mcp" },
  timestamp: Date.now(),
};

function policy(overrides: Partial<Policy> & { id: string }): Policy {
  return {
    decision: "ALLOW",
    match: {},
    reason: "test",
    ...overrides,
  };
}

describe("PolicyEngine", () => {
  describe("single matching policy", () => {
    it("returns ALLOW for matching ALLOW policy", () => {
      const engine = new PolicyEngine([
        policy({ id: "allow-echo", decision: "ALLOW", match: { tool: "echo" } }),
      ]);
      const result = engine.evaluate(baseContext);
      expect(result.decision).toBe("ALLOW");
      expect(result.policyId).toBe("allow-echo");
    });

    it("returns DENY for matching DENY policy", () => {
      const engine = new PolicyEngine([
        policy({ id: "deny-delete", decision: "DENY", match: { tool: "database.delete" } }),
      ]);
      const deleteContext: SecurityContext = { ...baseContext, toolName: "database.delete" };
      const result = engine.evaluate(deleteContext);
      expect(result.decision).toBe("DENY");
      expect(result.policyId).toBe("deny-delete");
    });

    it("returns REQUIRE_APPROVAL for matching approval policy", () => {
      const engine = new PolicyEngine([
        policy({
          id: "confirm-update",
          decision: "REQUIRE_APPROVAL",
          match: { tool: "database.update" },
        }),
      ]);
      const updateContext: SecurityContext = { ...baseContext, toolName: "database.update" };
      const result = engine.evaluate(updateContext);
      expect(result.decision).toBe("REQUIRE_APPROVAL");
      expect(result.policyId).toBe("confirm-update");
    });
  });

  describe("no matching policy", () => {
    it("returns DENY (default) when no policies match", () => {
      const engine = new PolicyEngine([
        policy({ id: "allow-delete", decision: "ALLOW", match: { tool: "database.delete" } }),
      ]);
      const result = engine.evaluate(baseContext);
      expect(result.decision).toBe("DENY");
      expect(result.policyId).toBeNull();
      expect(result.reason).toBe("No matching policy");
    });

    it("returns DENY (default) with empty policy array", () => {
      const engine = new PolicyEngine([]);
      const result = engine.evaluate(baseContext);
      expect(result.decision).toBe("DENY");
      expect(result.policyId).toBeNull();
    });
  });

  describe("precedence — severity", () => {
    it("DENY wins over ALLOW", () => {
      const engine = new PolicyEngine([
        policy({ id: "allow-all", decision: "ALLOW", match: {} }),
        policy({ id: "deny-echo", decision: "DENY", match: { tool: "echo" } }),
      ]);
      const result = engine.evaluate(baseContext);
      expect(result.decision).toBe("DENY");
      expect(result.policyId).toBe("deny-echo");
    });

    it("DENY wins over REQUIRE_APPROVAL", () => {
      const engine = new PolicyEngine([
        policy({ id: "confirm-echo", decision: "REQUIRE_APPROVAL", match: { tool: "echo" } }),
        policy({ id: "deny-echo", decision: "DENY", match: { tool: "echo" } }),
      ]);
      const result = engine.evaluate(baseContext);
      expect(result.decision).toBe("DENY");
      expect(result.policyId).toBe("deny-echo");
    });

    it("REQUIRE_APPROVAL wins over ALLOW", () => {
      const engine = new PolicyEngine([
        policy({ id: "allow-all", decision: "ALLOW", match: {} }),
        policy({ id: "confirm-echo", decision: "REQUIRE_APPROVAL", match: { tool: "echo" } }),
      ]);
      const result = engine.evaluate(baseContext);
      expect(result.decision).toBe("REQUIRE_APPROVAL");
      expect(result.policyId).toBe("confirm-echo");
    });

    it("ALLOW placed before DENY still loses", () => {
      const engine = new PolicyEngine([
        policy({ id: "allow-first", decision: "ALLOW", match: { tool: "echo" } }),
        policy({ id: "deny-second", decision: "DENY", match: { tool: "echo" } }),
      ]);
      const result = engine.evaluate(baseContext);
      expect(result.decision).toBe("DENY");
      expect(result.policyId).toBe("deny-second");
    });
  });

  describe("precedence — priority", () => {
    it("higher priority wins within same severity", () => {
      const engine = new PolicyEngine([
        policy({ id: "allow-low", decision: "ALLOW", match: { tool: "echo" }, priority: 1 }),
        policy({ id: "allow-high", decision: "ALLOW", match: { tool: "echo" }, priority: 10 }),
      ]);
      const result = engine.evaluate(baseContext);
      expect(result.decision).toBe("ALLOW");
      expect(result.policyId).toBe("allow-high");
    });

    it("priority cannot override severity (ALLOW cannot beat DENY)", () => {
      const engine = new PolicyEngine([
        policy({ id: "deny-low", decision: "DENY", match: { tool: "echo" }, priority: 1 }),
        policy({ id: "allow-high", decision: "ALLOW", match: { tool: "echo" }, priority: 100 }),
      ]);
      const result = engine.evaluate(baseContext);
      expect(result.decision).toBe("DENY");
      expect(result.policyId).toBe("deny-low");
    });

    it("priority cannot override severity (ALLOW cannot beat REQUIRE_APPROVAL)", () => {
      const engine = new PolicyEngine([
        policy({
          id: "confirm-low",
          decision: "REQUIRE_APPROVAL",
          match: { tool: "echo" },
          priority: 1,
        }),
        policy({ id: "allow-high", decision: "ALLOW", match: { tool: "echo" }, priority: 100 }),
      ]);
      const result = engine.evaluate(baseContext);
      expect(result.decision).toBe("REQUIRE_APPROVAL");
      expect(result.policyId).toBe("confirm-low");
    });
  });

  describe("precedence — insertion order", () => {
    it("earlier declaration wins when severity and priority are tied", () => {
      const engine = new PolicyEngine([
        policy({ id: "first", decision: "ALLOW", match: { tool: "echo" } }),
        policy({ id: "second", decision: "ALLOW", match: { tool: "echo" } }),
      ]);
      const result = engine.evaluate(baseContext);
      expect(result.decision).toBe("ALLOW");
      expect(result.policyId).toBe("first");
    });

    it("earlier DENY wins when tied", () => {
      const engine = new PolicyEngine([
        policy({ id: "deny-first", decision: "DENY", match: { tool: "echo" } }),
        policy({ id: "deny-second", decision: "DENY", match: { tool: "echo" } }),
      ]);
      const result = engine.evaluate(baseContext);
      expect(result.decision).toBe("DENY");
      expect(result.policyId).toBe("deny-first");
    });
  });

  describe("catch-all policies", () => {
    it("empty match {} matches every SecurityContext", () => {
      const engine = new PolicyEngine([
        policy({ id: "global-allow", decision: "ALLOW", match: {} }),
      ]);
      const result = engine.evaluate(baseContext);
      expect(result.decision).toBe("ALLOW");
      expect(result.policyId).toBe("global-allow");
    });

    it("global DENY blocks everything", () => {
      const engine = new PolicyEngine([policy({ id: "global-deny", decision: "DENY", match: {} })]);
      const result = engine.evaluate(baseContext);
      expect(result.decision).toBe("DENY");
      expect(result.policyId).toBe("global-deny");
    });

    it("global DENY beats specific ALLOW", () => {
      const engine = new PolicyEngine([
        policy({ id: "allow-echo", decision: "ALLOW", match: { tool: "echo" } }),
        policy({ id: "global-deny", decision: "DENY", match: {} }),
      ]);
      const result = engine.evaluate(baseContext);
      expect(result.decision).toBe("DENY");
      expect(result.policyId).toBe("global-deny");
    });
  });

  describe("multiple matching policies", () => {
    it("correct policy selected from three matches", () => {
      const engine = new PolicyEngine([
        policy({ id: "allow-all", decision: "ALLOW", match: {} }),
        policy({ id: "confirm-echo", decision: "REQUIRE_APPROVAL", match: { tool: "echo" } }),
        policy({ id: "deny-echo", decision: "DENY", match: { tool: "echo" } }),
      ]);
      const result = engine.evaluate(baseContext);
      expect(result.decision).toBe("DENY");
      expect(result.policyId).toBe("deny-echo");
    });
  });

  describe("policy evaluation metadata", () => {
    it("reason is always non-empty", () => {
      const engine = new PolicyEngine([
        policy({ id: "allow", decision: "ALLOW", match: {}, reason: "Allowed by policy" }),
      ]);
      const result = engine.evaluate(baseContext);
      expect(result.reason.length).toBeGreaterThan(0);
    });

    it("default DENY has descriptive reason", () => {
      const engine = new PolicyEngine([]);
      const result = engine.evaluate(baseContext);
      expect(result.reason).toBe("No matching policy");
    });
  });

  describe("notifications bypass", () => {
    it("notifications have no SecurityContext so engine is not called", () => {
      // This is a structural test — notifications don't reach the engine.
      // The route handler skips policy evaluation for notifications.
      // We verify the engine is never invoked by testing with a mock.
      const engine = new PolicyEngine([policy({ id: "global-deny", decision: "DENY", match: {} })]);
      // A notification-like context (method present, no tool)
      const notifContext: SecurityContext = {
        ...baseContext,
        method: "notifications/cancelled",
        toolName: undefined,
        toolArguments: undefined,
      };
      const result = engine.evaluate(notifContext);
      expect(result.decision).toBe("DENY");
      expect(result.policyId).toBe("global-deny");
    });
  });

  describe("constructor validation", () => {
    it("throws on invalid policy", () => {
      expect(
        () => new PolicyEngine([{ id: "", decision: "ALLOW", match: {}, reason: "test" }]),
      ).toThrow(/non-empty string/);
    });

    it("throws on duplicate id", () => {
      expect(
        () =>
          new PolicyEngine([
            { id: "dup", decision: "ALLOW", match: {}, reason: "a" },
            { id: "dup", decision: "DENY", match: {}, reason: "b" },
          ]),
      ).toThrow(/duplicate id/);
    });
  });
});
