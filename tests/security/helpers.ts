/**
 * Shared harness for the AegisMCP security suite.
 *
 * Every security test drives the REAL gateway over HTTP against PostgreSQL, so
 * the adversarial cases exercise authentication, policy, risk, approval, and
 * audit exactly as a production deployment does — no mocks of the security
 * path itself.
 *
 * Isolation rules:
 * - All identities/tools/policies are namespaced with a per-file prefix so suites
 *   sharing the database never interfere with each other.
 * - `clean()` deletes only this harness's prefix.
 */

import http from "node:http";
import { Pool } from "pg";
import { buildApp } from "@aegis/gateway/app";
import { runMigrations } from "@aegis/gateway/db";
import { buildPgRepositories } from "@aegis/gateway/repositories/pg";
import { DefaultCredentialService, ScryptSecretHasher } from "@aegis/gateway/security";

export const DATABASE_URL = process.env.DATABASE_URL;
export const hasDb = typeof DATABASE_URL === "string" && DATABASE_URL.length > 0;

export interface HarnessPolicy {
  readonly id: string;
  readonly decision: "ALLOW" | "DENY" | "REQUIRE_APPROVAL";
  readonly match: Record<string, unknown>;
  readonly reason: string;
  readonly priority?: number;
  readonly enabled?: boolean;
}

export interface GatewayHandle {
  readonly base: string;
  readonly app: ReturnType<typeof buildApp>;
  close(): Promise<void>;
}

function listen(server: http.Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") reject(new Error("no address"));
      else resolve(address.port);
    });
  });
}

export class SecurityHarness {
  readonly prefix: string;
  readonly identity: {
    agent: { id: string; name: string };
    server: { id: string; name: string; upstreamUrl: string };
  };
  readonly policies: HarnessPolicy[];
  readonly pool: Pool;
  private upstream!: http.Server;
  private upstreamUrl = "";

  /** Number of times the upstream MCP server was actually contacted. */
  connections = 0;

  constructor(prefix: string, policies: readonly HarnessPolicy[] = []) {
    this.prefix = prefix;
    this.identity = {
      agent: { id: `${prefix}gateway`, name: `${prefix}gateway` },
      server: { id: `${prefix}server`, name: `${prefix}server`, upstreamUrl: "" },
    };
    this.policies = [...policies];
    this.pool = new Pool({ connectionString: DATABASE_URL });
  }

  async setup(): Promise<void> {
    await runMigrations(this.pool);
    this.upstream = http.createServer((req, res) => {
      this.connections++;
      req.resume();
      req.on("end", () => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { executed: true } }));
      });
    });
    const port = await listen(this.upstream);
    this.upstreamUrl = `http://127.0.0.1:${port}/mcp`;
  }

  async teardown(): Promise<void> {
    await this.clean();
    await new Promise<void>((resolve) => this.upstream.close(() => resolve()));
    await this.pool.end();
  }

  async clean(): Promise<void> {
    const like = `${this.prefix}%`;
    await this.pool.query("DELETE FROM approvals WHERE agent_id LIKE $1", [like]);
    await this.pool.query("DELETE FROM audit_events WHERE server_id LIKE $1", [like]);
    await this.pool.query("DELETE FROM audit_events WHERE agent_id LIKE $1", [like]);
    await this.pool.query("DELETE FROM agent_credentials WHERE agent_id LIKE $1", [like]);
    await this.pool.query("DELETE FROM policies WHERE id LIKE $1", [like]);
    await this.pool.query("DELETE FROM agents WHERE id LIKE $1", [like]);
    await this.pool.query("DELETE FROM mcp_servers WHERE id LIKE $1", [like]);
    this.connections = 0;
  }

  repositories() {
    return buildPgRepositories(this.pool);
  }

  /** Register an agent (optionally with a role) and mint a valid credential. */
  async provision(agentId: string, role?: string): Promise<string> {
    await this.repositories().agents.upsert({
      id: agentId,
      name: agentId,
      ...(role !== undefined ? { role: role as never } : {}),
    } as never);
    const created = await new DefaultCredentialService(
      this.repositories(),
      new ScryptSecretHasher(),
    ).create({ agentId, agentName: agentId });
    return created.apiKey;
  }

  /** Provision a credential, then optionally expire or revoke it immediately. */
  async provisionWithState(
    agentId: string,
    state: { expiresAt?: number; revoked?: boolean },
  ): Promise<string> {
    await this.repositories().agents.upsert({ id: agentId, name: agentId } as never);
    const created = await new DefaultCredentialService(
      this.repositories(),
      new ScryptSecretHasher(),
    ).create({
      agentId,
      agentName: agentId,
      ...(state.expiresAt !== undefined ? { expiresAt: state.expiresAt } : {}),
    });
    if (state.revoked === true) {
      await this.repositories().credentials.revoke(created.keyId, Date.now());
    }
    return created.apiKey;
  }

  async startGateway(options?: {
    policies?: readonly HarnessPolicy[];
    authRequired?: boolean;
    serverId?: string;
    serverName?: string;
  }): Promise<GatewayHandle> {
    const serverId = options?.serverId ?? this.identity.server.id;
    const app = buildApp({
      databaseUrl: DATABASE_URL,
      upstreamUrl: this.upstreamUrl,
      identity: {
        agent: this.identity.agent,
        server: {
          id: serverId,
          name: options?.serverName ?? this.identity.server.name,
          upstreamUrl: this.upstreamUrl,
        },
      },
      policies: [...(options?.policies ?? this.policies)] as never,
      audit: { flushIntervalMs: 60_000, maxAttempts: 1 },
      auth: { required: options?.authRequired ?? true },
    });
    await app.listen({ port: 0, host: "127.0.0.1" });
    const address = app.server.address();
    if (!address || typeof address === "string") throw new Error("no gateway address");
    return {
      base: `http://127.0.0.1:${address.port}`,
      app,
      close: () => app.close(),
    };
  }

  mcp(
    base: string,
    apiKey: string | undefined,
    tool: string,
    args: Record<string, unknown> = {},
    extraHeaders: Record<string, string> = {},
    id: string | number = 1,
    method = "tools/call",
  ): Promise<Response> {
    return fetch(`${base}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(apiKey !== undefined ? { authorization: `Bearer ${apiKey}` } : {}),
        ...extraHeaders,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id,
        method,
        ...(method === "tools/call" ? { params: { name: tool, arguments: args } } : {}),
      }),
    });
  }

  admin(
    base: string,
    apiKey: string | undefined,
    path: string,
    init: RequestInit = {},
  ): Promise<Response> {
    const hasBody = init.body !== undefined;
    return fetch(`${base}/admin${path}`, {
      ...init,
      headers: {
        ...(hasBody ? { "content-type": "application/json" } : {}),
        ...(apiKey !== undefined ? { authorization: `Bearer ${apiKey}` } : {}),
        ...(init.headers ?? {}),
      },
    });
  }

  /** Create a PENDING approval and return its id (asserts the blocked response). */
  async createApproval(
    base: string,
    apiKey: string,
    tool: string,
    args: Record<string, unknown> = {},
    expectedCode = -32002,
  ): Promise<{ approvalId: string; error: { code: number; data?: unknown } }> {
    const response = await this.mcp(base, apiKey, tool, args, {}, `approve-${tool}`);
    const body = (await response.json()) as {
      error?: { code: number; data?: { approvalId?: string } };
    };
    if (body.error?.code !== expectedCode) {
      throw new Error(`expected ${expectedCode}, got ${JSON.stringify(body)}`);
    }
    const approvalId = body.error?.data?.approvalId;
    if (approvalId === undefined) throw new Error("no approval id in response");
    return { approvalId, error: body.error };
  }

  /** Approve an approval through the control plane as the given admin key. */
  async approveVia(
    base: string,
    adminKey: string,
    approvalId: string,
    reason?: string,
  ): Promise<Response> {
    return this.admin(base, adminKey, `/approvals/${approvalId}/approve`, {
      method: "POST",
      body: JSON.stringify(reason !== undefined ? { reason } : {}),
    });
  }

  async denyVia(base: string, adminKey: string, approvalId: string): Promise<Response> {
    return this.admin(base, adminKey, `/approvals/${approvalId}/deny`, {
      method: "POST",
      body: JSON.stringify({}),
    });
  }

  async approvalRow(approvalId: string): Promise<Record<string, unknown> | undefined> {
    const { rows } = await this.pool.query("SELECT * FROM approvals WHERE id = $1", [approvalId]);
    return rows[0] as Record<string, unknown> | undefined;
  }

  async auditRowsFor(approvalId: string): Promise<Record<string, unknown>[]> {
    const { rows } = await this.pool.query(
      "SELECT * FROM audit_events WHERE approval_id = $1 ORDER BY id",
      [approvalId],
    );
    return rows as Record<string, unknown>[];
  }
}
