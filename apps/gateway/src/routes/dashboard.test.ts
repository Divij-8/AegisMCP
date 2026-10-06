import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { buildApp } from "../app.js";
import type { TrustedIdentityConfig } from "../security/identity.js";

const baseIdentity: TrustedIdentityConfig = {
  agent: { id: "dashboard-test-agent", name: "dashboard-test-agent", role: "AUDITOR" },
  server: {
    id: "dashboard-test-server",
    name: "dashboard-test-server",
    upstreamUrl: "http://127.0.0.1:9/mcp",
  },
};

let app: ReturnType<typeof buildApp>;

beforeAll(async () => {
  // DB-free: the dashboard is a static shell and needs no persistence.
  app = buildApp({ identity: baseIdentity, databaseUrl: null });
  await app.ready();
});

afterAll(async () => {
  await app.close();
});

describe("GET /dashboard", () => {
  it("serves the HTML shell", async () => {
    const response = await app.inject({ method: "GET", url: "/dashboard" });

    expect(response.statusCode).toBe(200);
    expect(response.headers["content-type"]).toContain("text/html");
    expect(response.payload).toContain("<!doctype html>");
    expect(response.payload).toContain("/dashboard/app.js");
    expect(response.payload).toContain("/dashboard/app.css");
  });

  it("sets a strict Content-Security-Policy with no inline permissions", async () => {
    const response = await app.inject({ method: "GET", url: "/dashboard" });
    const csp = String(response.headers["content-security-policy"]);

    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("connect-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("base-uri 'none'");
    expect(csp).toContain("form-action 'none'");
    // The whole point of the policy: nothing inline may execute.
    expect(csp).not.toContain("unsafe-inline");
    expect(csp).not.toContain("unsafe-eval");
  });

  it("hardens the other response headers", async () => {
    const response = await app.inject({ method: "GET", url: "/dashboard" });

    expect(response.headers["x-content-type-options"]).toBe("nosniff");
    expect(response.headers["referrer-policy"]).toBe("no-referrer");
    expect(response.headers["cache-control"]).toBe("no-store");
  });

  it("embeds no server state, credential material, or configuration", async () => {
    const response = await app.inject({ method: "GET", url: "/dashboard" });

    // The configured identity must not leak into a shell served pre-auth.
    expect(response.payload).not.toContain("dashboard-test-agent");
    expect(response.payload).not.toContain("dashboard-test-server");
    // The shell may name the `amcp_…` key format in its input placeholder, but
    // must never contain a well-formed credential (keyId + 64-hex secret).
    expect(response.payload).not.toMatch(/amcp_[0-9a-f]{32}_[0-9a-f]{64}/);
    expect(response.payload).not.toContain("DATABASE_URL");
  });

  it("is byte-identical across differently configured gateways", async () => {
    const other = buildApp({
      identity: {
        agent: { id: "another-agent", name: "another-agent", role: "ADMIN" },
        server: {
          id: "another-server",
          name: "another-server",
          upstreamUrl: "http://127.0.0.1:9/mcp",
        },
      },
      databaseUrl: null,
    });
    try {
      await other.ready();
      const a = await app.inject({ method: "GET", url: "/dashboard" });
      const b = await other.inject({ method: "GET", url: "/dashboard" });
      // Proves the shell interpolates nothing from server state.
      expect(b.payload).toBe(a.payload);
    } finally {
      await other.close();
    }
  });
});

describe("GET /dashboard assets", () => {
  it("serves the script as same-origin JavaScript", async () => {
    const response = await app.inject({ method: "GET", url: "/dashboard/app.js" });

    expect(response.statusCode).toBe(200);
    expect(response.headers["content-type"]).toContain("application/javascript");
    expect(response.headers["content-security-policy"]).toContain("script-src 'self'");
  });

  it("serves the stylesheet", async () => {
    const response = await app.inject({ method: "GET", url: "/dashboard/app.css" });

    expect(response.statusCode).toBe(200);
    expect(response.headers["content-type"]).toContain("text/css");
    expect(response.headers["content-security-policy"]).toContain("style-src 'self'");
  });

  it("never renders API data via innerHTML", async () => {
    const response = await app.inject({ method: "GET", url: "/dashboard/app.js" });

    // Security invariant: every dynamic value is written with textContent, so
    // a hostile policy reason or audit detail is displayed as literal text.
    expect(response.payload).not.toContain("innerHTML");
    expect(response.payload).not.toContain("outerHTML");
    expect(response.payload).not.toContain("insertAdjacentHTML");
    expect(response.payload).not.toContain("document.write");
  });

  it("reads the credential from sessionStorage, not localStorage", async () => {
    const response = await app.inject({ method: "GET", url: "/dashboard/app.js" });

    expect(response.payload).toContain("sessionStorage");
    expect(response.payload).not.toContain("localStorage");
  });
});
