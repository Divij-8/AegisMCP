import { describe, it, expect } from "vitest";
import { PolicyStore } from "./store.js";
import type { Page, PolicyRepository } from "../repositories/types.js";
import type { Policy } from "./types.js";
import type { SecurityContext } from "../mcp/types.js";

const policyA: Policy = {
  id: "allow-echo",
  decision: "ALLOW",
  match: { tool: "echo" },
  reason: "echo allowed",
};

const policyB: Policy = {
  id: "deny-delete",
  decision: "DENY",
  match: { tool: "database.delete" },
  reason: "delete forbidden",
};

function fakeContext(toolName: string | undefined, method = "tools/call"): SecurityContext {
  return {
    requestId: 1,
    protocolVersion: "2026-07-28",
    method,
    toolName,
    toolArguments: undefined,
    agent: { id: "agent-1", name: "agent-1" },
    server: { id: "server-1", name: "server-1", upstreamUrl: "http://127.0.0.1:3001/mcp" },
    timestamp: Date.now(),
  };
}

class FakePolicyRepository implements PolicyRepository {
  constructor(public policies: readonly Policy[] = []) {}

  async listEnabled(): Promise<readonly Policy[]> {
    return [...this.policies];
  }

  async upsert(): Promise<void> {
    throw new Error("not implemented");
  }

  async setEnabled(): Promise<void> {
    throw new Error("not implemented");
  }

  async listAll(): Promise<Page<Policy>> {
    return { items: [...this.policies], total: this.policies.length, limit: 0, offset: 0 };
  }

  async findById(): Promise<Policy | null> {
    throw new Error("not implemented");
  }

  async remove(): Promise<boolean> {
    throw new Error("not implemented");
  }
}

class ThrowingPolicyRepository implements PolicyRepository {
  async listEnabled(): Promise<readonly Policy[]> {
    throw new Error("db down");
  }

  async upsert(): Promise<void> {
    throw new Error("not implemented");
  }

  async setEnabled(): Promise<void> {
    throw new Error("not implemented");
  }

  async listAll(): Promise<Page<Policy>> {
    throw new Error("db down");
  }

  async findById(): Promise<Policy | null> {
    throw new Error("db down");
  }

  async remove(): Promise<boolean> {
    throw new Error("db down");
  }
}

describe("PolicyStore", () => {
  it("serves requests from the initial snapshot without a repository", () => {
    const store = new PolicyStore(null, [policyA]);
    const engine = store.buildEngine();
    expect(engine.evaluate(fakeContext("echo")).decision).toBe("ALLOW");
    expect(engine.evaluate(fakeContext("other")).decision).toBe("DENY");
  });

  it("buildEngine reflects a completed reload on subsequent calls (no staleness)", async () => {
    const repo = new FakePolicyRepository([policyA]);
    const store = new PolicyStore(repo, []);

    expect(store.buildEngine().evaluate(fakeContext("echo")).decision).toBe("DENY");

    await store.reload();
    expect(store.buildEngine().evaluate(fakeContext("echo")).decision).toBe("ALLOW");

    repo.policies = [policyA, policyB];
    await store.reload();
    expect(store.buildEngine().evaluate(fakeContext("database.delete")).decision).toBe("DENY");
    expect(store.buildEngine().evaluate(fakeContext("database.delete")).policyId).toBe(
      "deny-delete",
    );
  });

  it("reload returns whether the snapshot changed", async () => {
    const repo = new FakePolicyRepository([policyA]);
    const store = new PolicyStore(repo, [policyA]);

    await expect(store.reload()).resolves.toBe(false);

    repo.policies = [policyA, policyB];
    await expect(store.reload()).resolves.toBe(true);
  });

  it("reload throws on repository failure without mutating the snapshot", async () => {
    const store = new PolicyStore(new ThrowingPolicyRepository(), [policyA]);

    await expect(store.reload()).rejects.toThrow("db down");

    // last-known-good snapshot still serving
    expect(store.buildEngine().evaluate(fakeContext("echo")).decision).toBe("ALLOW");
  });

  it("reloadSafe swallows failures and keeps serving the last-known-good snapshot", async () => {
    const store = new PolicyStore(new ThrowingPolicyRepository(), [policyA]);

    await expect(store.reloadSafe()).resolves.toBe(false);
    expect(store.buildEngine().evaluate(fakeContext("echo")).decision).toBe("ALLOW");
  });

  it("reload rejects invalid policies from the repository (fail-closed)", async () => {
    const invalid: Policy = {
      id: "",
      decision: "ALLOW",
      match: {},
      reason: "bad",
    };
    const repo = new FakePolicyRepository([invalid]);
    const store = new PolicyStore(repo, [policyA]);

    await expect(store.reload()).rejects.toThrow();
    // unchanged snapshot still active
    expect(store.buildEngine().evaluate(fakeContext("echo")).decision).toBe("ALLOW");
  });

  it("snapshot is immutable from the outside", () => {
    const store = new PolicyStore(null, [policyA]);
    const snapshot = store.getSnapshot();
    expect(() => {
      (snapshot.policies as Policy[]).push(policyB);
    }).toThrow();
  });

  it("reload with no repository is a no-op returning false", async () => {
    const store = new PolicyStore(null, [policyA]);
    await expect(store.reload()).resolves.toBe(false);
  });
});
