import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { buildApp } from "../app.js";

let app: ReturnType<typeof buildApp>;

beforeAll(async () => {
  app = buildApp({ databaseUrl: null });
  await app.ready();
});

afterAll(async () => {
  await app.close();
});

describe("GET /health", () => {
  it("reports liveness", async () => {
    const response = await app.inject({ method: "GET", url: "/health" });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: "ok" });
  });
});

describe("GET /ready", () => {
  it("is ready without persistence", async () => {
    const response = await app.inject({ method: "GET", url: "/ready" });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: "ready", persistence: false });
  });
});

describe("GET /metrics", () => {
  it("exposes aggregate counters without secrets", async () => {
    const response = await app.inject({ method: "GET", url: "/metrics" });
    expect(response.statusCode).toBe(200);
    const body = response.json() as {
      counters: Record<string, number>;
      policies: { active: number };
      audit: { queued: number };
    };
    expect(body.policies.active).toBe(0);
    expect(typeof body.audit.queued).toBe("number");
    expect(JSON.stringify(body)).not.toContain("secret");
  });
});
