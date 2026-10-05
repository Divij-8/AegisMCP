import { describe, it, expect } from "vitest";
import { matchesPolicy } from "./matcher.js";
import type { SecurityContext } from "../mcp/types.js";

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

describe("matchesPolicy", () => {
  describe("exact agent match", () => {
    it("matches when agent.id equals policy agent", () => {
      expect(matchesPolicy(baseContext, { agent: "alpha-agent" })).toBe(true);
    });

    it("does not match when agent.id differs", () => {
      expect(matchesPolicy(baseContext, { agent: "beta-agent" })).toBe(false);
    });
  });

  describe("exact server match", () => {
    it("matches when server.id equals policy server", () => {
      expect(matchesPolicy(baseContext, { server: "mock-server" })).toBe(true);
    });

    it("does not match when server.id differs", () => {
      expect(matchesPolicy(baseContext, { server: "other-server" })).toBe(false);
    });
  });

  describe("exact method match", () => {
    it("matches when method equals policy method", () => {
      expect(matchesPolicy(baseContext, { method: "tools/call" })).toBe(true);
    });

    it("does not match when method differs", () => {
      expect(matchesPolicy(baseContext, { method: "tools/list" })).toBe(false);
    });
  });

  describe("exact tool match", () => {
    it("matches when toolName equals policy tool", () => {
      expect(matchesPolicy(baseContext, { tool: "echo" })).toBe(true);
    });

    it("does not match when toolName differs", () => {
      expect(matchesPolicy(baseContext, { tool: "database.delete" })).toBe(false);
    });
  });

  describe("wildcard / unspecified fields", () => {
    it("empty match matches every context", () => {
      expect(matchesPolicy(baseContext, {})).toBe(true);
    });

    it("unspecified agent matches any agent", () => {
      expect(matchesPolicy(baseContext, { tool: "echo" })).toBe(true);
    });

    it("unspecified tool matches any tool", () => {
      expect(matchesPolicy(baseContext, { agent: "alpha-agent" })).toBe(true);
    });

    it("unspecified server matches any server", () => {
      expect(matchesPolicy(baseContext, { method: "tools/call" })).toBe(true);
    });

    it("unspecified method matches any method", () => {
      expect(matchesPolicy(baseContext, { tool: "echo" })).toBe(true);
    });
  });

  describe("multiple fields (AND logic)", () => {
    it("matches when all specified fields match", () => {
      expect(matchesPolicy(baseContext, { agent: "alpha-agent", tool: "echo" })).toBe(true);
    });

    it("does not match when one field differs", () => {
      expect(matchesPolicy(baseContext, { agent: "alpha-agent", tool: "database.delete" })).toBe(
        false,
      );
    });

    it("matches when all four fields match", () => {
      expect(
        matchesPolicy(baseContext, {
          agent: "alpha-agent",
          server: "mock-server",
          method: "tools/call",
          tool: "echo",
        }),
      ).toBe(true);
    });

    it("does not match when any one of four fields differs", () => {
      expect(
        matchesPolicy(baseContext, {
          agent: "alpha-agent",
          server: "mock-server",
          method: "tools/call",
          tool: "wrong-tool",
        }),
      ).toBe(false);
    });
  });

  describe("tools/list (no toolName)", () => {
    it("does not match a tool-specific policy", () => {
      const listContext: SecurityContext = {
        ...baseContext,
        method: "tools/list",
        toolName: undefined,
        toolArguments: undefined,
      };
      expect(matchesPolicy(listContext, { tool: "echo" })).toBe(false);
    });

    it("matches a method-level policy", () => {
      const listContext: SecurityContext = {
        ...baseContext,
        method: "tools/list",
        toolName: undefined,
        toolArguments: undefined,
      };
      expect(matchesPolicy(listContext, { method: "tools/list" })).toBe(true);
    });

    it("matches a wildcard policy", () => {
      const listContext: SecurityContext = {
        ...baseContext,
        method: "tools/list",
        toolName: undefined,
        toolArguments: undefined,
      };
      expect(matchesPolicy(listContext, {})).toBe(true);
    });
  });

  describe("unknown methods", () => {
    it("matches a wildcard policy", () => {
      const customContext: SecurityContext = {
        ...baseContext,
        method: "custom/unknown",
        toolName: undefined,
        toolArguments: undefined,
      };
      expect(matchesPolicy(customContext, {})).toBe(true);
    });

    it("matches a method-specific policy", () => {
      const customContext: SecurityContext = {
        ...baseContext,
        method: "custom/unknown",
        toolName: undefined,
        toolArguments: undefined,
      };
      expect(matchesPolicy(customContext, { method: "custom/unknown" })).toBe(true);
    });

    it("does not match a different method policy", () => {
      const customContext: SecurityContext = {
        ...baseContext,
        method: "custom/unknown",
        toolName: undefined,
        toolArguments: undefined,
      };
      expect(matchesPolicy(customContext, { method: "tools/call" })).toBe(false);
    });
  });

  describe("argument constraints", () => {
    it("matches when an equals constraint is satisfied", () => {
      expect(matchesPolicy(baseContext, { arguments: { message: { equals: "hello" } } })).toBe(
        true,
      );
    });

    it("does not match when an equals constraint differs", () => {
      expect(matchesPolicy(baseContext, { arguments: { message: { equals: "bye" } } })).toBe(false);
    });

    it("matches when a oneOf constraint includes the value", () => {
      expect(
        matchesPolicy(baseContext, { arguments: { message: { oneOf: ["hi", "hello"] } } }),
      ).toBe(true);
    });

    it("does not match when oneOf excludes the value", () => {
      expect(matchesPolicy(baseContext, { arguments: { message: { oneOf: ["hi", "bye"] } } })).toBe(
        false,
      );
    });

    it("does not match when the constrained argument is absent", () => {
      expect(
        matchesPolicy(
          { ...baseContext, toolArguments: { other: 1 } },
          { arguments: { message: { equals: "hello" } } },
        ),
      ).toBe(false);
    });

    it("does not match when there are no tool arguments at all", () => {
      expect(
        matchesPolicy(
          { ...baseContext, toolArguments: undefined },
          { arguments: { message: { equals: "hello" } } },
        ),
      ).toBe(false);
    });

    it("supports structural equality for object values", () => {
      const context: SecurityContext = {
        ...baseContext,
        toolArguments: { filter: { a: 1, b: 2 } },
      };
      expect(matchesPolicy(context, { arguments: { filter: { equals: { b: 2, a: 1 } } } })).toBe(
        true,
      );
    });

    it("fails closed for an empty constraint object", () => {
      expect(matchesPolicy(baseContext, { arguments: { message: {} } })).toBe(false);
    });
  });
});
