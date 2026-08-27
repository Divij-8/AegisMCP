import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { resolveIdentity } from "./identity.js";

describe("resolveIdentity", () => {
  const envBackup: Record<string, string | undefined> = {};

  beforeEach(() => {
    for (const key of ["AGENT_ID", "AGENT_NAME", "SERVER_ID", "SERVER_NAME", "UPSTREAM_URL"]) {
      envBackup[key] = process.env[key];
    }
  });

  afterEach(() => {
    for (const key of Object.keys(envBackup)) {
      if (envBackup[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = envBackup[key];
      }
    }
  });

  it("returns defaults when no env vars set", () => {
    delete process.env.AGENT_ID;
    delete process.env.AGENT_NAME;
    delete process.env.SERVER_ID;
    delete process.env.SERVER_NAME;
    delete process.env.UPSTREAM_URL;

    const identity = resolveIdentity();
    expect(identity.agent.id).toBe("default-agent");
    expect(identity.agent.name).toBe("default-agent");
    expect(identity.server.id).toBe("aegis-mock-mcp-server");
    expect(identity.server.name).toBe("aegis-mock-mcp-server");
    expect(identity.server.upstreamUrl).toBe("http://127.0.0.1:3001/mcp");
  });

  it("reads from environment variables", () => {
    process.env.AGENT_ID = "env-agent-id";
    process.env.AGENT_NAME = "env-agent-name";

    const identity = resolveIdentity();
    expect(identity.agent.id).toBe("env-agent-id");
    expect(identity.agent.name).toBe("env-agent-name");
  });

  it("overrides take precedence over env vars", () => {
    process.env.AGENT_ID = "env-agent";

    const identity = resolveIdentity({ agentId: "override-agent" });
    expect(identity.agent.id).toBe("override-agent");
  });

  it("returns frozen objects", () => {
    const identity = resolveIdentity();
    expect(Object.isFrozen(identity)).toBe(true);
    expect(Object.isFrozen(identity.agent)).toBe(true);
    expect(Object.isFrozen(identity.server)).toBe(true);
  });
});
