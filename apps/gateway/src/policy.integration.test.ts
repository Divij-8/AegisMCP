import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { buildApp } from "./app.js";

let app: ReturnType<typeof buildApp>;

describe("policy enforcement", () => {
  describe("empty policy array — deny-all default", () => {
    beforeAll(async () => {
      app = buildApp({ policies: [] });
      await app.listen({ port: 0, host: "127.0.0.1" });
    });

    afterAll(async () => {
      await app.close();
    });

    it("denies tools/call with -32003 error", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/mcp",
        headers: { "content-type": "application/json" },
        payload: {
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: "echo", arguments: { message: "hi" } },
        },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.payload);
      expect(body.jsonrpc).toBe("2.0");
      expect(body.id).toBe(1);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe(-32003);
      expect(body.error.message).toBe("No matching policy");
    });

    it("denies tools/list", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/mcp",
        headers: { "content-type": "application/json" },
        payload: {
          jsonrpc: "2.0",
          id: 2,
          method: "tools/list",
        },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.payload);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe(-32003);
    });

    it("forwards notifications without policy evaluation", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/mcp",
        headers: { "content-type": "application/json" },
        payload: {
          jsonrpc: "2.0",
          method: "notifications/cancelled",
          params: { requestId: 1, reason: "test" },
        },
      });

      // Notifications have no id, so they're forwarded upstream.
      // Since upstream is unavailable, we get a 502.
      expect(response.statusCode).toBe(502);
    });
  });

  describe("ALLOW policy for specific tool", () => {
    beforeAll(async () => {
      app = buildApp({
        policies: [
          {
            id: "allow-echo",
            decision: "ALLOW",
            match: { tool: "echo" },
            reason: "Echo is safe",
          },
        ],
      });
      await app.listen({ port: 0, host: "127.0.0.1" });
    });

    afterAll(async () => {
      await app.close();
    });

    it("allows tools/call with matching tool name", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/mcp",
        headers: { "content-type": "application/json" },
        payload: {
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: "echo", arguments: { message: "hi" } },
        },
      });

      // Policy allows → reaches upstream → 502 because upstream unavailable
      expect(response.statusCode).toBe(502);
    });

    it("denies tools/call with non-matching tool name", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/mcp",
        headers: { "content-type": "application/json" },
        payload: {
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: { name: "database.delete", arguments: {} },
        },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.payload);
      expect(body.error.code).toBe(-32003);
      expect(body.error.message).toBe("No matching policy");
    });

    it("denies tools/list (not matching tool-specific policy)", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/mcp",
        headers: { "content-type": "application/json" },
        payload: {
          jsonrpc: "2.0",
          id: 3,
          method: "tools/list",
        },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.payload);
      expect(body.error.code).toBe(-32003);
    });
  });

  describe("DENY policy for specific tool", () => {
    beforeAll(async () => {
      app = buildApp({
        policies: [
          {
            id: "global-allow",
            decision: "ALLOW",
            match: {},
            reason: "Allow all by default",
          },
          {
            id: "deny-delete",
            decision: "DENY",
            match: { tool: "database.delete" },
            reason: "Delete is forbidden",
          },
        ],
      });
      await app.listen({ port: 0, host: "127.0.0.1" });
    });

    afterAll(async () => {
      await app.close();
    });

    it("denies tools/call with matching DENY tool", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/mcp",
        headers: { "content-type": "application/json" },
        payload: {
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: "database.delete", arguments: { id: 42 } },
        },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.payload);
      expect(body.error.code).toBe(-32003);
      expect(body.error.message).toBe("Delete is forbidden");
    });

    it("allows tools/call with non-matching tool", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/mcp",
        headers: { "content-type": "application/json" },
        payload: {
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: { name: "echo", arguments: { message: "hi" } },
        },
      });

      // Global ALLOW applies → reaches upstream → 502
      expect(response.statusCode).toBe(502);
    });

    it("allows tools/list (global ALLOW matches)", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/mcp",
        headers: { "content-type": "application/json" },
        payload: {
          jsonrpc: "2.0",
          id: 3,
          method: "tools/list",
        },
      });

      // Global ALLOW applies → reaches upstream → 502
      expect(response.statusCode).toBe(502);
    });
  });

  describe("REQUIRE_APPROVAL policy", () => {
    beforeAll(async () => {
      app = buildApp({
        policies: [
          {
            id: "global-allow",
            decision: "ALLOW",
            match: {},
            reason: "Allow all",
          },
          {
            id: "confirm-destroy",
            decision: "REQUIRE_APPROVAL",
            match: { tool: "system.destroy" },
            reason: "Destructive action requires approval",
          },
        ],
      });
      await app.listen({ port: 0, host: "127.0.0.1" });
    });

    afterAll(async () => {
      await app.close();
    });

    it("returns -32002 for matching approval policy", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/mcp",
        headers: { "content-type": "application/json" },
        payload: {
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: "system.destroy", arguments: {} },
        },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.payload);
      expect(body.error.code).toBe(-32002);
      expect(body.error.message).toBe("Destructive action requires approval");
    });

    it("allows non-matching tool through", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/mcp",
        headers: { "content-type": "application/json" },
        payload: {
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: { name: "echo", arguments: { message: "hi" } },
        },
      });

      expect(response.statusCode).toBe(502);
    });
  });

  describe("multiple matching policies — precedence", () => {
    beforeAll(async () => {
      app = buildApp({
        policies: [
          {
            id: "allow-echo",
            decision: "ALLOW",
            match: { tool: "echo" },
            reason: "Allow echo",
          },
          {
            id: "deny-echo",
            decision: "DENY",
            match: { tool: "echo" },
            reason: "Deny echo override",
          },
        ],
      });
      await app.listen({ port: 0, host: "127.0.0.1" });
    });

    afterAll(async () => {
      await app.close();
    });

    it("DENY wins over ALLOW for same tool", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/mcp",
        headers: { "content-type": "application/json" },
        payload: {
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: "echo", arguments: { message: "hi" } },
        },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.payload);
      expect(body.error.code).toBe(-32003);
      expect(body.error.message).toBe("Deny echo override");
    });
  });
});
