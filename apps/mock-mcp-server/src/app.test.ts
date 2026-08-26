import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Client } from "@modelcontextprotocol/client";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { buildApp } from "./app.js";

let app: ReturnType<typeof buildApp>;
let baseUrl: string;

beforeAll(async () => {
  app = buildApp();
  await new Promise<void>((resolve) => {
    app.server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = app.server.address();
  if (!address || typeof address === "string") throw new Error("no address");
  baseUrl = `http://127.0.0.1:${address.port}/mcp`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => {
    app.server.close(() => resolve());
  });
});

async function createClient() {
  const client = new Client(
    { name: "test-client", version: "0.0.1" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } },
  );
  const transport = new StreamableHTTPClientTransport(new URL(baseUrl));
  await client.connect(transport);
  return { client, transport };
}

describe("mock MCP server", () => {
  it("connects via modern 2026-07-28 protocol", async () => {
    const { client, transport } = await createClient();
    try {
      const { tools } = await client.listTools();
      expect(tools).toHaveLength(1);
      expect(tools[0]!.name).toBe("echo");
    } finally {
      await transport.close();
    }
  });

  it("echo tool returns the input message", async () => {
    const { client, transport } = await createClient();
    try {
      const result = await client.callTool({
        name: "echo",
        arguments: { message: "hello from test" },
      });
      expect(result).toMatchObject({
        content: [{ type: "text", text: "hello from test" }],
      });
    } finally {
      await transport.close();
    }
  });

  it("rejects legacy 2025-style requests", async () => {
    const response = await fetch(baseUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-03-26",
          capabilities: {},
          clientInfo: { name: "legacy-client", version: "0.0.1" },
        },
      }),
    });
    expect(response.status).toBe(400);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body).toHaveProperty("error");
  });
});
