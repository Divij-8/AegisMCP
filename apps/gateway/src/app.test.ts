import { describe, it, expect, afterAll } from "vitest";
import { buildApp } from "./app.js";

const app = buildApp();

afterAll(async () => {
  await app.close();
});

describe("buildApp", () => {
  it("creates a Fastify instance", () => {
    expect(app).toBeDefined();
    expect(typeof app.inject).toBe("function");
  });
});

describe("GET /health", () => {
  it("returns 200", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/health",
    });

    expect(response.statusCode).toBe(200);
  });

  it("returns { status: 'ok' }", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/health",
    });

    expect(response.json()).toEqual({ status: "ok" });
  });
});

describe("POST /mcp", () => {
  it("returns 501", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/mcp",
    });

    expect(response.statusCode).toBe(501);
  });

  it("returns NotImplemented error structure", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/mcp",
    });

    expect(response.json()).toEqual({
      error: "NotImplemented",
      message: "MCP proxy not yet implemented",
    });
  });
});
