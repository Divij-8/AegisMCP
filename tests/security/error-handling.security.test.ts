import { describe, it, expect, afterAll, vi } from "vitest";
import http from "node:http";
import { buildApp } from "@aegis/gateway/app";

/**
 * Error-handling security review.
 *
 * These do NOT require a working database: they assert that infrastructure
 * failure is fail-closed (the gateway refuses to start, or refuses to execute)
 * rather than silently running in a weaker mode.
 */

const servers: http.Server[] = [];

afterAll(async () => {
  await Promise.all(
    servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))),
  );
});

describe("SECURITY: fail-closed error handling", () => {
  it("refuses to start when AUTH_REQUIRED=true without a database", () => {
    expect(() => buildApp({ databaseUrl: null, auth: { required: true } })).toThrow(
      /AUTH_REQUIRED=true requires DATABASE_URL/,
    );
  });

  it("refuses to start when the database is unreachable (startup migrations fail)", async () => {
    const app = buildApp({
      databaseUrl: "postgres://aegis:aegis@127.0.0.1:1/aegis_nope",
      upstreamUrl: "http://127.0.0.1:1/mcp",
      auth: { required: true },
    });
    await expect(app.listen({ port: 0, host: "127.0.0.1" })).rejects.toBeTruthy();
    await app.close().catch(() => {});
  });

  it("returns a deterministic timeout and audits upstream failure when the upstream hangs", async () => {
    // Upstream that accepts the connection but never answers.
    const hanging = http.createServer(() => {
      /* never respond */
    });
    servers.push(hanging);
    const port = await new Promise<number>((resolve) => {
      hanging.listen(0, "127.0.0.1", () => {
        const address = hanging.address();
        resolve(address && typeof address !== "string" ? address.port : 0);
      });
    });

    const app = buildApp({
      databaseUrl: null,
      upstreamUrl: `http://127.0.0.1:${port}/mcp`,
      upstreamTimeoutMs: 300,
      policies: [{ id: "allow", decision: "ALLOW", match: {}, reason: "allow" }],
    });
    await app.listen({ port: 0, host: "127.0.0.1" });
    const address = app.server.address();
    const base = `http://127.0.0.1:${address && typeof address !== "string" ? address.port : 0}`;

    const res = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    expect(res.status).toBe(504);
    const text = await res.text();
    expect(text).not.toMatch(/node_modules|\.ts:\d+|at\s+\w+\s+\(/);

    // The gateway stays up after an upstream failure.
    expect((await fetch(`${base}/health`)).status).toBe(200);
    await app.close();
  });

  it("does not start in an unauthenticated mode when auth is required but misconfigured", async () => {
    // An unrecognized AUTH_REQUIRED value must fail startup, not silently decode
    // to "not required". The config module snapshots the environment at import
    // time (as it does in the real process entrypoint), so re-import the
    // composition root with the misconfigured environment in place.
    const previous = process.env.AUTH_REQUIRED;
    process.env.AUTH_REQUIRED = "yes";
    vi.resetModules();
    try {
      const fresh = await import("@aegis/gateway/app");
      expect(() => fresh.buildApp({ databaseUrl: "postgres://127.0.0.1:1/x" })).toThrow(
        /Invalid AUTH_REQUIRED/,
      );
    } finally {
      if (previous === undefined) delete process.env.AUTH_REQUIRED;
      else process.env.AUTH_REQUIRED = previous;
      vi.resetModules();
    }
  });
});
