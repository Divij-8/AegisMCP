import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import Fastify from "fastify";
import http from "node:http";
import { mcpRoutes } from "./mcp.js";
import { PolicyStore } from "../policy/store.js";
import type { AgentAuthenticator, AuthResult } from "../security/authenticator.js";
import type { AuditEvent, AuditSink, AuditSinkStats } from "../audit/types.js";
import type { Policy } from "../policy/types.js";
import type { TrustedIdentityConfig } from "../security/identity.js";

class RecordingSink implements AuditSink {
  readonly events: AuditEvent[] = [];
  record(event: AuditEvent): void {
    this.events.push(event);
  }
  async flush(): Promise<void> {}
  async close(): Promise<void> {}
  stats(): AuditSinkStats {
    return { queued: 0, flushed: this.events.length, failed: 0, dropped: 0 };
  }
}

class FakeAuthenticator implements AgentAuthenticator {
  readonly enforced = true;
  constructor(private readonly result: AuthResult) {}
  async authenticate(): Promise<AuthResult> {
    return this.result;
  }
}

const identity: TrustedIdentityConfig = {
  agent: { id: "static-agent", name: "static-agent" },
  server: { id: "route-server", name: "route-server", upstreamUrl: "http://placeholder.invalid" },
};

const validResult: AuthResult = {
  ok: true,
  credential: { agent: { id: "auth-agent", name: "Authenticated Agent" }, keyId: "a".repeat(32) },
};

let upstream: http.Server;
let upstreamPort: number;
let upstreamConnections = 0;

beforeAll(async () => {
  upstream = http.createServer((req, res) => {
    upstreamConnections++;
    req.resume();
    req.on("end", () => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { ok: true } }));
    });
  });
  upstreamPort = await new Promise<number>((resolve) => {
    upstream.listen(0, "127.0.0.1", () => {
      const addr = upstream.address();
      if (!addr || typeof addr === "string") throw new Error("no upstream address");
      resolve(addr.port);
    });
  });
});

afterAll(async () => {
  await new Promise<void>((resolve) => upstream.close(() => resolve()));
});

beforeEach(() => {
  upstreamConnections = 0;
});

async function buildGateway(options: {
  authenticator: AgentAuthenticator;
  policies?: readonly Policy[];
  policyStore?: PolicyStore;
}): Promise<{ url: string; sink: RecordingSink; close: () => Promise<void> }> {
  const app = Fastify({ logger: false });
  const sink = new RecordingSink();
  const policyStore = options.policyStore ?? new PolicyStore(null, options.policies ?? []);
  void app.register(mcpRoutes, {
    upstreamUrl: `http://127.0.0.1:${upstreamPort}/mcp`,
    upstreamTimeoutMs: 5_000,
    identity,
    runtime: { policyStore, auditSink: sink, authenticator: options.authenticator },
  });
  await app.listen({ port: 0, host: "127.0.0.1" });
  const addr = app.server.address();
  if (!addr || typeof addr === "string") throw new Error("no gateway address");
  return {
    url: `http://127.0.0.1:${addr.port}/mcp`,
    sink,
    close: () => app.close(),
  };
}

const toolCall = (tool: string) =>
  JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name: tool, arguments: {} },
  });

async function post(url: string, body: string, headers: Record<string, string> = {}) {
  return fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body,
  });
}

describe("mcp auth gate", () => {
  it("rejects a missing credential with 401 and never contacts upstream", async () => {
    const { url, sink, close } = await buildGateway({
      authenticator: new FakeAuthenticator({ ok: false, reason: "missing", keyId: null }),
      policies: [{ id: "allow-all", decision: "ALLOW", match: {}, reason: "open" }],
    });

    const response = await post(url, toolCall("echo"));
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toBe("Bearer");
    const body = (await response.json()) as { error?: { code: number; message: string } };
    expect(body.error?.code).toBe(-32004);
    expect(body.error?.message).toBe("Missing credentials");

    expect(upstreamConnections).toBe(0);
    expect(sink.events).toHaveLength(1);
    const event = sink.events[0]!;
    expect(event.eventType).toBe("auth");
    expect(event.outcome).toBe("auth_failed");
    expect(event.authFailureReason).toBe("missing");
    expect(event.agentId).toBeNull();
    expect(event.keyId).toBeUndefined();

    await close();
  });

  it("rejects an invalid credential with a generic 401 and records the public key id", async () => {
    const keyId = "b".repeat(32);
    const { url, sink, close } = await buildGateway({
      authenticator: new FakeAuthenticator({ ok: false, reason: "invalid", keyId }),
    });

    const response = await post(url, toolCall("echo"), {
      authorization: `Bearer amcp_${keyId}_${"c".repeat(64)}`,
    });
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toBeNull();
    const body = (await response.json()) as { error?: { code: number; message: string } };
    expect(body.error?.code).toBe(-32004);
    // Generic: revoked/expired/unknown/invalid are indistinguishable to clients.
    expect(body.error?.message).toBe("Authentication failed");

    expect(upstreamConnections).toBe(0);
    expect(sink.events[0]?.authFailureReason).toBe("invalid");
    expect(sink.events[0]?.keyId).toBe(keyId);

    await close();
  });

  it("returns 503 when the credential store fails", async () => {
    const { url, sink, close } = await buildGateway({
      authenticator: new FakeAuthenticator({
        ok: false,
        reason: "error",
        keyId: null,
        error: new Error("db down"),
      }),
    });

    const response = await post(url, toolCall("echo"));
    expect(response.status).toBe(503);
    const body = (await response.json()) as { error?: { code: number; message: string } };
    expect(body.error?.code).toBe(-32004);
    expect(body.error?.message).toBe("Authentication unavailable");

    expect(upstreamConnections).toBe(0);
    expect(sink.events[0]?.authFailureReason).toBe("error");

    await close();
  });

  it("short-circuits before policy evaluation when authentication fails", async () => {
    const explodingPolicyStore = {
      buildEngine() {
        throw new Error("policy must not be evaluated for an unauthenticated request");
      },
    } as unknown as PolicyStore;

    const { url, close } = await buildGateway({
      authenticator: new FakeAuthenticator({ ok: false, reason: "unknown", keyId: null }),
      policyStore: explodingPolicyStore,
    });

    const response = await post(url, toolCall("echo"));
    expect(response.status).toBe(401);
    expect(upstreamConnections).toBe(0);

    await close();
  });

  it("forwards an authenticated request and audits the authenticated agent", async () => {
    const { url, sink, close } = await buildGateway({
      authenticator: new FakeAuthenticator(validResult),
      policies: [{ id: "allow-echo", decision: "ALLOW", match: { tool: "echo" }, reason: "safe" }],
    });

    const response = await post(url, toolCall("echo"), {
      authorization: `Bearer amcp_${"a".repeat(32)}_${"d".repeat(64)}`,
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { result?: unknown };
    expect(body.result).toBeDefined();

    expect(upstreamConnections).toBe(1);
    const request = sink.events.find((event) => event.eventType === "request");
    expect(request).toBeDefined();
    expect(request?.agentId).toBe("auth-agent");
    expect(request?.outcome).toBe("forwarded");

    await close();
  });

  it("rejects an unauthenticated notification and never reaches upstream", async () => {
    const { url, sink, close } = await buildGateway({
      authenticator: new FakeAuthenticator({ ok: false, reason: "missing", keyId: null }),
    });

    const response = await post(
      url,
      JSON.stringify({
        jsonrpc: "2.0",
        method: "notifications/cancelled",
        params: { requestId: 1 },
      }),
    );
    expect(response.status).toBe(401);
    expect(upstreamConnections).toBe(0);

    const event = sink.events[0]!;
    expect(event.eventType).toBe("auth");
    expect(event.method).toBe("notifications/cancelled");
    expect(event.agentId).toBeNull();

    await close();
  });

  it("forwards an authenticated notification and audits the authenticated agent", async () => {
    const { url, sink, close } = await buildGateway({
      authenticator: new FakeAuthenticator(validResult),
    });

    const response = await post(
      url,
      JSON.stringify({
        jsonrpc: "2.0",
        method: "notifications/cancelled",
        params: { requestId: 1 },
      }),
      { "x-api-key": `amcp_${"a".repeat(32)}_${"d".repeat(64)}` },
    );
    expect(response.status).toBe(200);
    expect(upstreamConnections).toBe(1);

    const event = sink.events[0]!;
    expect(event.eventType).toBe("notification");
    expect(event.agentId).toBe("auth-agent");

    await close();
  });
});
