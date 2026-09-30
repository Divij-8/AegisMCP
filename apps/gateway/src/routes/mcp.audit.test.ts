import { describe, it, expect, beforeAll, afterAll } from "vitest";
import Fastify from "fastify";
import http from "node:http";
import { mcpRoutes } from "./mcp.js";
import { PolicyStore } from "../policy/store.js";
import { BufferedAuditSink } from "../audit/sink.js";
import type { AuditEventRepository } from "../repositories/types.js";
import type { AuditEvent } from "../audit/types.js";
import type { Policy } from "../policy/types.js";
import type { TrustedIdentityConfig } from "../security/identity.js";
import { StaticIdentityAuthenticator } from "../security/authenticator.js";

class RecordingAuditRepository implements AuditEventRepository {
  readonly events: AuditEvent[] = [];
  async insertBatch(events: readonly AuditEvent[]): Promise<void> {
    this.events.push(...events);
  }
}

const identity: TrustedIdentityConfig = {
  agent: { id: "route-agent", name: "route-agent" },
  server: {
    id: "route-server",
    name: "route-server",
    upstreamUrl: "http://placeholder.invalid/mcp",
  },
};

function buildUpstream() {
  return http.createServer((req, res) => {
    // Drain request body, then answer with a valid JSON-RPC result.
    req.resume();
    req.on("end", () => {
      const body = JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        result: { content: [{ type: "text", text: "upstream-ok" }] },
      });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(body);
    });
  });
}

function listen(server: http.Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") throw new Error("no address");
      resolve(addr.port);
    });
  });
}

describe("mcp routes — policy store + audit integration (no DB)", () => {
  let upstream: http.Server;
  let upstreamPort: number;

  beforeAll(async () => {
    upstream = buildUpstream();
    upstreamPort = await listen(upstream);
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => upstream.close(() => resolve()));
  });

  function buildGateway(policies: readonly Policy[]) {
    const app = Fastify({ logger: false });
    const repo = new RecordingAuditRepository();
    const auditSink = new BufferedAuditSink(repo, { flushIntervalMs: 60_000 });
    const policyStore = new PolicyStore(null, policies);
    const runtime = {
      policyStore,
      auditSink,
      authenticator: new StaticIdentityAuthenticator(identity.agent),
    };
    void app.register(mcpRoutes, {
      upstreamUrl: `http://127.0.0.1:${upstreamPort}/mcp`,
      upstreamTimeoutMs: 5_000,
      identity,
      runtime,
    });
    return { app, repo, auditSink, policyStore, runtime };
  }

  it("audits an ALLOWed tools/call with outcome forwarded and upstream status", async () => {
    const { app, repo, auditSink } = buildGateway([
      { id: "allow-echo", decision: "ALLOW", match: { tool: "echo" }, reason: "safe" },
    ]);
    await app.listen({ port: 0, host: "127.0.0.1" });
    const addr = app.server.address();
    const url = `http://127.0.0.1:${addr && typeof addr !== "string" ? addr.port : 0}/mcp`;

    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "req-1",
        method: "tools/call",
        params: { name: "echo", arguments: { message: "SECRET-PAYLOAD" } },
      }),
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as { result?: unknown };
    expect(body.result).toBeDefined();

    await auditSink.flush();

    expect(repo.events).toHaveLength(1);
    const event = repo.events[0]!;
    expect(event.eventType).toBe("request");
    expect(event.requestId).toBe("req-1");
    expect(event.agentId).toBe("route-agent");
    expect(event.serverId).toBe("route-server");
    expect(event.method).toBe("tools/call");
    expect(event.toolName).toBe("echo");
    expect(event.decision).toBe("ALLOW");
    expect(event.policyId).toBe("allow-echo");
    expect(event.outcome).toBe("forwarded");
    expect(event.upstreamStatus).toBe(200);
    expect(event.latencyMs).toBeGreaterThanOrEqual(0);
    // No raw tool arguments anywhere in the persisted event.
    expect(JSON.stringify(event)).not.toContain("SECRET-PAYLOAD");
    expect(event.toolArgumentsRedaction).toBeUndefined();

    await app.close();
  });

  it("audits a DENYed request with outcome blocked and no upstream status", async () => {
    const { app, repo, auditSink } = buildGateway([
      { id: "deny-delete", decision: "DENY", match: { tool: "database.delete" }, reason: "nope" },
    ]);
    await app.listen({ port: 0, host: "127.0.0.1" });
    const addr = app.server.address();
    const url = `http://127.0.0.1:${addr && typeof addr !== "string" ? addr.port : 0}/mcp`;

    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 7,
        method: "tools/call",
        params: { name: "database.delete", arguments: { id: 1 } },
      }),
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as { error?: { code: number } };
    expect(body.error?.code).toBe(-32003);

    await auditSink.flush();
    expect(repo.events).toHaveLength(1);
    const event = repo.events[0]!;
    expect(event.decision).toBe("DENY");
    expect(event.outcome).toBe("blocked");
    expect(event.upstreamStatus).toBeNull();

    await app.close();
  });

  it("audits notifications with eventType notification and null decision", async () => {
    const { app, repo, auditSink } = buildGateway([
      { id: "allow-all", decision: "ALLOW", match: {}, reason: "open" },
    ]);
    await app.listen({ port: 0, host: "127.0.0.1" });
    const addr = app.server.address();
    const url = `http://127.0.0.1:${addr && typeof addr !== "string" ? addr.port : 0}/mcp`;

    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "notifications/cancelled",
        params: { requestId: 1 },
      }),
    });
    expect(response.status).toBe(200);

    await auditSink.flush();
    expect(repo.events).toHaveLength(1);
    const event = repo.events[0]!;
    expect(event.eventType).toBe("notification");
    expect(event.requestId).toBeNull();
    expect(event.decision).toBeNull();
    expect(event.policyId).toBeNull();
    expect(event.method).toBe("notifications/cancelled");

    await app.close();
  });

  it("uses fresh policy snapshots per request — reload affects subsequent requests", async () => {
    const initial: Policy[] = [];
    const { app, repo, auditSink, policyStore } = buildGateway(initial);
    await app.listen({ port: 0, host: "127.0.0.1" });
    const addr = app.server.address();
    const url = `http://127.0.0.1:${addr && typeof addr !== "string" ? addr.port : 0}/mcp`;

    const payload = (id: number) => ({
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id,
        method: "tools/call",
        params: { name: "echo", arguments: {} },
      }),
    });

    // No policies yet → default DENY (-32003), never reaches upstream.
    const denied = await fetch(url, payload(1));
    expect(((await denied.json()) as { error?: { code: number } }).error?.code).toBe(-32003);

    // Simulate a policy configuration change + reload.
    const seeded: Policy = {
      id: "allow-echo",
      decision: "ALLOW",
      match: { tool: "echo" },
      reason: "now allowed",
    };
    Object.defineProperty(policyStore, "reload", {
      value: async () => {
        (policyStore as unknown as { snapshot: unknown }).snapshot = {
          policies: [seeded],
          loadedAt: Date.now(),
        };
        return true;
      },
    });
    await policyStore.reload();

    const allowed = await fetch(url, payload(2));
    const allowedBody = (await allowed.json()) as { result?: unknown; error?: unknown };
    expect(allowedBody.result).toBeDefined();
    expect(allowedBody.error).toBeUndefined();

    await auditSink.flush();
    const decisions = repo.events
      .filter((event) => event.eventType === "request")
      .map((event) => event.decision);
    expect(decisions).toEqual(["DENY", "ALLOW"]);

    await app.close();
  });
});
