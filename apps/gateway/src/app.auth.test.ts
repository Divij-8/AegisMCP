import { describe, it, expect, afterEach, vi } from "vitest";
import { buildApp } from "./app.js";

/**
 * The AUTH_REQUIRED matrix is enforced at composition time. These tests cover
 * the no-database cells (the database cells live in tests/integration).
 */

async function requestMcp(app: ReturnType<typeof buildApp>): Promise<number> {
  await app.listen({ port: 0, host: "127.0.0.1" });
  const address = app.server.address();
  if (!address || typeof address === "string") throw new Error("no address");
  const response = await fetch(`http://127.0.0.1:${address.port}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
  const body = (await response.json()) as { error?: { code: number } };
  await app.close();
  return body.error?.code ?? 0;
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.resetModules();
});

describe("AUTH_REQUIRED startup matrix (no database)", () => {
  it("fails at startup when auth is required without a database", () => {
    expect(() => buildApp({ databaseUrl: null, auth: { required: true } })).toThrow(
      /AUTH_REQUIRED=true requires DATABASE_URL/,
    );
  });

  it("fails at startup when AUTH_REQUIRED is set in the environment without a database", async () => {
    vi.resetModules();
    vi.stubEnv("AUTH_REQUIRED", "true");
    vi.stubEnv("DATABASE_URL", "");

    const { buildApp: freshBuildApp } = await import("./app.js");
    expect(() => freshBuildApp()).toThrow(/AUTH_REQUIRED=true requires DATABASE_URL/);
  });

  it("accepts case-insensitive AUTH_REQUIRED=true", async () => {
    vi.resetModules();
    vi.stubEnv("AUTH_REQUIRED", "TRUE");
    vi.stubEnv("DATABASE_URL", "");

    const { buildApp: freshBuildApp } = await import("./app.js");
    // "TRUE" decoded to true, so the no-database requirement still trips.
    expect(() => freshBuildApp()).toThrow(/AUTH_REQUIRED=true requires DATABASE_URL/);
  });

  it("fails at startup when AUTH_REQUIRED is unrecognized (fail-closed parsing)", async () => {
    vi.resetModules();
    vi.stubEnv("AUTH_REQUIRED", "yes");
    vi.stubEnv("DATABASE_URL", "");

    const { buildApp: freshBuildApp } = await import("./app.js");
    // Must not silently fall back to the unauthenticated compatibility mode.
    expect(() => freshBuildApp()).toThrow(/Invalid AUTH_REQUIRED/);
  });

  it("allows an explicit override to remain unauthenticated", () => {
    expect(() => buildApp({ databaseUrl: null, auth: { required: false } })).not.toThrow();
  });

  it("preserves unauthenticated behavior by default (no database, AUTH_REQUIRED unset)", async () => {
    vi.resetModules();
    vi.stubEnv("AUTH_REQUIRED", "");
    vi.stubEnv("DATABASE_URL", "");

    const { buildApp: freshBuildApp } = await import("./app.js");
    const app = freshBuildApp({
      upstreamUrl: "http://127.0.0.1:1/mcp",
      databaseUrl: null,
      policies: [{ id: "allow-all", decision: "ALLOW", match: {}, reason: "open" }],
    });

    const errorCode = await requestMcp(app);
    // The request was processed without credentials: no auth error (-32004).
    expect(errorCode).not.toBe(-32004);
  });
});
