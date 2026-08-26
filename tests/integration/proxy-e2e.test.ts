import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Client } from "@modelcontextprotocol/client";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { buildApp as buildMockServer } from "@aegis/mock-mcp-server/app";
import { buildApp as buildGateway } from "@aegis/gateway/app";

let mockServer: ReturnType<typeof buildMockServer>;
let gateway: ReturnType<typeof buildGateway>;
let gatewayUrl: string;

beforeAll(async () => {
  mockServer = buildMockServer();
  await new Promise<void>((resolve) => {
    mockServer.server.listen(0, "127.0.0.1", () => resolve());
  });
  const mockAddr = mockServer.server.address();
  if (!mockAddr || typeof mockAddr === "string") throw new Error("no mock address");

  const upstreamUrl = `http://127.0.0.1:${mockAddr.port}/mcp`;

  gateway = buildGateway({ upstreamUrl });
  await gateway.listen({ port: 0, host: "127.0.0.1" });
  const gwAddr = gateway.server.address();
  if (!gwAddr || typeof gwAddr === "string") throw new Error("no gateway address");
  gatewayUrl = `http://127.0.0.1:${gwAddr.port}/mcp`;
});

afterAll(async () => {
  await gateway.close();
  await new Promise<void>((resolve) => {
    mockServer.server.close(() => resolve());
  });
});

async function createClient() {
  const client = new Client(
    { name: "e2e-test-client", version: "0.0.1" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } },
  );
  const transport = new StreamableHTTPClientTransport(new URL(gatewayUrl));
  await client.connect(transport);
  return { client, transport };
}

describe("AegisMCP proxy end-to-end", () => {
  it("client connects through Aegis gateway", async () => {
    const { client, transport } = await createClient();
    try {
      const { tools } = await client.listTools();
      expect(tools).toBeDefined();
      expect(Array.isArray(tools)).toBe(true);
    } finally {
      await transport.close();
    }
  });

  it("tools/list returns echo tool", async () => {
    const { client, transport } = await createClient();
    try {
      const { tools } = await client.listTools();
      expect(tools).toHaveLength(1);
      expect(tools[0]!.name).toBe("echo");
    } finally {
      await transport.close();
    }
  });

  it("echo tool invocation returns correct result", async () => {
    const { client, transport } = await createClient();
    try {
      const result = await client.callTool({
        name: "echo",
        arguments: { message: "proxy test" },
      });
      expect(result).toMatchObject({
        content: [{ type: "text", text: "proxy test" }],
      });
    } finally {
      await transport.close();
    }
  });

  it("unknown tool error propagates from upstream", async () => {
    const { client, transport } = await createClient();
    try {
      await expect(
        client.callTool({
          name: "nonexistent",
          arguments: {},
        }),
      ).rejects.toThrow();
    } finally {
      await transport.close();
    }
  });

  it("gateway remains healthy after proxy operations", async () => {
    const response = await fetch(gatewayUrl.replace("/mcp", "/health"));
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body).toEqual({ status: "ok" });
  });
});
