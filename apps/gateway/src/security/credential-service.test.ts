import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { DefaultCredentialService } from "./credential-service.js";
import type { SecretHasher } from "./hash.js";
import { parseApiKey } from "./credential.js";
import { buildInMemoryRepositories } from "../repositories/memory.js";

class FakeHasher implements SecretHasher {
  readonly algorithm = "scrypt-v1";
  generateSalt(): string {
    return "fakesalt";
  }
  async hash(secret: string, salt: string): Promise<string> {
    return createHash("sha256").update(`${salt}:${secret}`).digest("hex");
  }
  async verify(secret: string, salt: string, expectedHash: string): Promise<boolean> {
    return (await this.hash(secret, salt)) === expectedHash;
  }
}

const NOW = 10_000;

function makeService(): {
  service: DefaultCredentialService;
  repositories: ReturnType<typeof buildInMemoryRepositories>;
} {
  const repositories = buildInMemoryRepositories();
  const service = new DefaultCredentialService(repositories, new FakeHasher(), () => NOW);
  return { service, repositories };
}

describe("DefaultCredentialService", () => {
  it("creates a credential whose api key parses back to the returned key id", async () => {
    const { service } = makeService();
    const created = await service.create({ agentId: "agent-a" });

    const parsed = parseApiKey(created.apiKey);
    expect(parsed).not.toBeNull();
    expect(parsed?.keyId).toBe(created.keyId);
    expect(created.agent).toEqual({ id: "agent-a", name: "agent-a" });
  });

  it("registers the agent when it does not exist yet", async () => {
    const { service, repositories } = makeService();
    await service.create({ agentId: "agent-new", agentName: "New Agent" });

    await expect(repositories.agents.findById("agent-new")).resolves.toEqual({
      id: "agent-new",
      name: "New Agent",
    });
  });

  it("preserves the registered name of an existing agent", async () => {
    const { service, repositories } = makeService();
    await repositories.agents.upsert({ id: "agent-existing", name: "Canonical Name" });

    const created = await service.create({ agentId: "agent-existing" });
    expect(created.agent.name).toBe("Canonical Name");
  });

  it("stores only a hash — never the plaintext secret", async () => {
    const { service, repositories } = makeService();
    const created = await service.create({ agentId: "agent-a", label: "primary" });
    const secret = parseApiKey(created.apiKey)!.secret;

    const record = await repositories.credentials.findByKeyId(created.keyId);
    expect(record).not.toBeNull();
    expect(record?.secretHash).not.toBe(secret);
    expect(record?.secretHash).not.toContain(secret);
    expect(JSON.stringify(record)).not.toContain(secret);
    expect(record?.label).toBe("primary");
    expect(record?.revokedAt).toBeNull();
  });

  it("revokes once and reports subsequent revocations as no-ops", async () => {
    const { service } = makeService();
    const created = await service.create({ agentId: "agent-a" });

    await expect(service.revoke(created.keyId)).resolves.toBe(true);
    await expect(service.revoke(created.keyId)).resolves.toBe(false);
  });

  it("lists summaries without any secret material", async () => {
    const { service } = makeService();
    const first = await service.create({ agentId: "agent-a", label: "first" });
    const second = await service.create({ agentId: "agent-a", label: "second" });
    await service.revoke(second.keyId, NOW);

    const summaries = await service.listByAgent("agent-a");
    expect(summaries).toHaveLength(2);

    const firstSummary = summaries.find((summary) => summary.keyId === first.keyId)!;
    const secondSummary = summaries.find((summary) => summary.keyId === second.keyId)!;
    expect(firstSummary.active).toBe(true);
    expect(secondSummary.active).toBe(false);
    expect(secondSummary.revokedAt).toBe(NOW);

    const serialized = JSON.stringify(summaries);
    expect(serialized).not.toContain("secretHash");
    expect(serialized).not.toContain("salt");
    expect(serialized).not.toContain(parseApiKey(first.apiKey)!.secret);
  });

  it("marks an expired credential inactive", async () => {
    const { service } = makeService();
    const created = await service.create({ agentId: "agent-a", expiresAt: NOW - 1 });

    const summaries = await service.listByAgent("agent-a");
    expect(summaries[0]?.keyId).toBe(created.keyId);
    expect(summaries[0]?.active).toBe(false);
  });
});
