import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { buildApp } from "./app.js";

let app: ReturnType<typeof buildApp>;
let baseUrl: string;

beforeAll(async () => {
  app = buildApp();
  await app.listen({ port: 0, host: "127.0.0.1" });
  const address = app.server.address();
  if (!address || typeof address === "string") throw new Error("no address");
  baseUrl = `http://127.0.0.1:${address.port}`;
});

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
  it("returns 502 when upstream is unavailable", async () => {
    const response = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/list",
      }),
    });

    expect(response.status).toBe(502);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body).toHaveProperty("error", "BadGateway");
  });

  it("does not crash on upstream failure", async () => {
    await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/list",
      }),
    });

    const healthResponse = await fetch(`${baseUrl}/health`);
    expect(healthResponse.status).toBe(200);
  });
});
