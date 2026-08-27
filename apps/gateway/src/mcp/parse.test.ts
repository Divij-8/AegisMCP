import { describe, it, expect } from "vitest";
import { parseMcpRequest, serializeJsonRpcError } from "./parse.js";
import type { TrustedIdentityConfig } from "../security/identity.js";
import { PARSE_ERROR, INVALID_REQUEST, INVALID_PARAMS } from "@modelcontextprotocol/server";

const identity: TrustedIdentityConfig = {
  agent: { id: "test-agent", name: "test-agent" },
  server: { id: "test-server", name: "test-server", upstreamUrl: "http://127.0.0.1:3001/mcp" },
};

function buf(obj: unknown): Buffer {
  return Buffer.from(JSON.stringify(obj));
}

describe("parseMcpRequest", () => {
  describe("malformed input", () => {
    it("returns PARSE_ERROR for invalid JSON", () => {
      const result = parseMcpRequest(Buffer.from("{invalid"), identity);
      expect(result.kind).toBe("error");
      if (result.kind === "error") {
        expect(result.error.code).toBe(PARSE_ERROR);
      }
    });

    it("returns INVALID_REQUEST for a JSON array", () => {
      const result = parseMcpRequest(buf([1, 2, 3]), identity);
      expect(result.kind).toBe("error");
      if (result.kind === "error") {
        expect(result.error.code).toBe(INVALID_REQUEST);
      }
    });

    it("returns INVALID_REQUEST for a JSON null", () => {
      const result = parseMcpRequest(buf(null), identity);
      expect(result.kind).toBe("error");
      if (result.kind === "error") {
        expect(result.error.code).toBe(INVALID_REQUEST);
      }
    });

    it("returns INVALID_REQUEST when jsonrpc is missing", () => {
      const result = parseMcpRequest(buf({ id: 1, method: "tools/list" }), identity);
      expect(result.kind).toBe("error");
      if (result.kind === "error") {
        expect(result.error.code).toBe(INVALID_REQUEST);
      }
    });

    it("returns INVALID_REQUEST when jsonrpc is not '2.0'", () => {
      const result = parseMcpRequest(buf({ jsonrpc: "1.0", id: 1, method: "tools/list" }), identity);
      expect(result.kind).toBe("error");
      if (result.kind === "error") {
        expect(result.error.code).toBe(INVALID_REQUEST);
      }
    });

    it("returns INVALID_REQUEST when method is missing", () => {
      const result = parseMcpRequest(buf({ jsonrpc: "2.0", id: 1 }), identity);
      expect(result.kind).toBe("error");
      if (result.kind === "error") {
        expect(result.error.code).toBe(INVALID_REQUEST);
      }
    });
  });

  describe("notifications", () => {
    it("returns notification kind for messages without id", () => {
      const result = parseMcpRequest(
        buf({ jsonrpc: "2.0", method: "notifications/cancelled", params: {} }),
        identity,
      );
      expect(result.kind).toBe("notification");
    });
  });

  describe("tools/list", () => {
    it("produces SecurityContext with method and no tool fields", () => {
      const result = parseMcpRequest(
        buf({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
        identity,
      );
      expect(result.kind).toBe("request");
      if (result.kind === "request") {
        expect(result.context.requestId).toBe(1);
        expect(result.context.method).toBe("tools/list");
        expect(result.context.toolName).toBeUndefined();
        expect(result.context.toolArguments).toBeUndefined();
      }
    });

    it("preserves numeric request id", () => {
      const result = parseMcpRequest(
        buf({ jsonrpc: "2.0", id: 42, method: "tools/list" }),
        identity,
      );
      expect(result.kind).toBe("request");
      if (result.kind === "request") {
        expect(result.context.requestId).toBe(42);
      }
    });

    it("preserves string request id", () => {
      const result = parseMcpRequest(
        buf({ jsonrpc: "2.0", id: "abc-123", method: "tools/list" }),
        identity,
      );
      expect(result.kind).toBe("request");
      if (result.kind === "request") {
        expect(result.context.requestId).toBe("abc-123");
      }
    });
  });

  describe("tools/call", () => {
    it("extracts tool name and arguments", () => {
      const result = parseMcpRequest(
        buf({
          jsonrpc: "2.0",
          id: 7,
          method: "tools/call",
          params: { name: "echo", arguments: { message: "hello" } },
        }),
        identity,
      );
      expect(result.kind).toBe("request");
      if (result.kind === "request") {
        expect(result.context.toolName).toBe("echo");
        expect(result.context.toolArguments).toEqual({ message: "hello" });
        expect(result.context.method).toBe("tools/call");
        expect(result.context.requestId).toBe(7);
      }
    });

    it("returns INVALID_PARAMS when name is missing", () => {
      const result = parseMcpRequest(
        buf({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { arguments: {} } }),
        identity,
      );
      expect(result.kind).toBe("error");
      if (result.kind === "error") {
        expect(result.error.code).toBe(INVALID_PARAMS);
      }
    });

    it("returns INVALID_PARAMS when params is missing entirely", () => {
      const result = parseMcpRequest(
        buf({ jsonrpc: "2.0", id: 1, method: "tools/call" }),
        identity,
      );
      expect(result.kind).toBe("error");
      if (result.kind === "error") {
        expect(result.error.code).toBe(INVALID_PARAMS);
      }
    });

    it("returns INVALID_PARAMS when arguments is not an object", () => {
      const result = parseMcpRequest(
        buf({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: "echo", arguments: "not-an-object" },
        }),
        identity,
      );
      expect(result.kind).toBe("error");
      if (result.kind === "error") {
        expect(result.error.code).toBe(INVALID_PARAMS);
      }
    });

    it("accepts tools/call without arguments (arguments is optional)", () => {
      const result = parseMcpRequest(
        buf({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "echo" } }),
        identity,
      );
      expect(result.kind).toBe("request");
      if (result.kind === "request") {
        expect(result.context.toolName).toBe("echo");
        expect(result.context.toolArguments).toBeUndefined();
      }
    });
  });

  describe("server/discover", () => {
    it("produces SecurityContext with method and no tool fields", () => {
      const result = parseMcpRequest(
        buf({
          jsonrpc: "2.0",
          id: 3,
          method: "server/discover",
          params: { _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" } },
        }),
        identity,
      );
      expect(result.kind).toBe("request");
      if (result.kind === "request") {
        expect(result.context.method).toBe("server/discover");
        expect(result.context.toolName).toBeUndefined();
        expect(result.context.toolArguments).toBeUndefined();
      }
    });
  });

  describe("unknown methods", () => {
    it("produces SecurityContext for unknown methods (forwardable)", () => {
      const result = parseMcpRequest(
        buf({ jsonrpc: "2.0", id: 99, method: "custom/unknown", params: {} }),
        identity,
      );
      expect(result.kind).toBe("request");
      if (result.kind === "request") {
        expect(result.context.method).toBe("custom/unknown");
      }
    });
  });

  describe("protocol version extraction", () => {
    it("extracts from _meta envelope (2026-07-28)", () => {
      const result = parseMcpRequest(
        buf({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/list",
          params: {
            _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" },
          },
        }),
        identity,
      );
      expect(result.kind).toBe("request");
      if (result.kind === "request") {
        expect(result.context.protocolVersion).toBe("2026-07-28");
      }
    });

    it("extracts from params.protocolVersion (legacy)", () => {
      const result = parseMcpRequest(
        buf({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/list",
          params: { protocolVersion: "2025-11-25" },
        }),
        identity,
      );
      expect(result.kind).toBe("request");
      if (result.kind === "request") {
        expect(result.context.protocolVersion).toBe("2025-11-25");
      }
    });

    it("returns undefined when no version present", () => {
      const result = parseMcpRequest(
        buf({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
        identity,
      );
      expect(result.kind).toBe("request");
      if (result.kind === "request") {
        expect(result.context.protocolVersion).toBeUndefined();
      }
    });
  });

  describe("identity", () => {
    it("uses trusted config identity, not client data", () => {
      const result = parseMcpRequest(
        buf({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
        identity,
      );
      expect(result.kind).toBe("request");
      if (result.kind === "request") {
        expect(result.context.agent).toEqual({ id: "test-agent", name: "test-agent" });
        expect(result.context.server).toEqual({
          id: "test-server",
          name: "test-server",
          upstreamUrl: "http://127.0.0.1:3001/mcp",
        });
      }
    });
  });

  describe("timestamp", () => {
    it("sets a timestamp near Date.now()", () => {
      const before = Date.now();
      const result = parseMcpRequest(
        buf({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
        identity,
      );
      const after = Date.now();
      expect(result.kind).toBe("request");
      if (result.kind === "request") {
        expect(result.context.timestamp).toBeGreaterThanOrEqual(before);
        expect(result.context.timestamp).toBeLessThanOrEqual(after);
      }
    });
  });

  describe("buffer integrity", () => {
    it("does not mutate the original buffer", () => {
      const original = buf({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "echo", arguments: { message: "test" } },
      });
      const copy = Buffer.from(original);
      parseMcpRequest(original, identity);
      expect(original.equals(copy)).toBe(true);
    });
  });
});

describe("serializeJsonRpcError", () => {
  it("produces valid JSON-RPC error with null id for parse errors", () => {
    const body = serializeJsonRpcError({ code: PARSE_ERROR, message: "Parse error" }, null);
    const parsed = JSON.parse(body);
    expect(parsed).toEqual({
      jsonrpc: "2.0",
      id: null,
      error: { code: -32700, message: "Parse error" },
    });
  });

  it("echoes the original request id", () => {
    const body = serializeJsonRpcError(
      { code: INVALID_PARAMS, message: "Invalid params" },
      42,
    );
    const parsed = JSON.parse(body);
    expect(parsed.id).toBe(42);
    expect(parsed.error.code).toBe(-32602);
  });

  it("includes data field when present", () => {
    const body = serializeJsonRpcError(
      { code: INVALID_PARAMS, message: "Invalid params", data: { field: "name" } },
      "req-1",
    );
    const parsed = JSON.parse(body);
    expect(parsed.error.data).toEqual({ field: "name" });
  });

  it("omits data field when undefined", () => {
    const body = serializeJsonRpcError(
      { code: INVALID_REQUEST, message: "Invalid Request" },
      null,
    );
    const parsed = JSON.parse(body);
    expect(parsed.error).not.toHaveProperty("data");
  });
});
