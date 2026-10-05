import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { runCredentialCli } from "./cli.js";
import type { CliIo } from "./cli.js";
import { DefaultCredentialService } from "../security/credential-service.js";
import type { CredentialService } from "../security/credential-service.js";
import type { SecretHasher } from "../security/hash.js";
import { parseApiKey } from "../security/credential.js";
import { InMemoryAgentRepository, buildInMemoryRepositories } from "../repositories/memory.js";
import type { CredentialRepository } from "../repositories/types.js";

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

function capture(): { io: CliIo; out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: { out: (line) => out.push(line), err: (line) => err.push(line) },
    out,
    err,
  };
}

function makeService(repositories = buildInMemoryRepositories()): CredentialService {
  return new DefaultCredentialService(repositories, new FakeHasher(), () => 1_000);
}

const KEY_PATTERN = /amcp_[0-9a-f]{32}_[0-9a-f]{64}/;

describe("runCredentialCli create", () => {
  it("prints the API key exactly once and never to stderr", async () => {
    const repositories = buildInMemoryRepositories();
    const { io, out, err } = capture();

    const code = await runCredentialCli(["create", "--agent", "agent-a", "--label", "ci"], io, {
      service: makeService(repositories),
    });

    expect(code).toBe(0);
    const stdout = out.join("\n");
    expect(stdout.match(/amcp_/g)?.length).toBe(1);
    expect(stdout).toMatch(KEY_PATTERN);
    expect(err.join("\n")).not.toContain("amcp_");

    // Only the hash is stored; the printed secret never reaches the repository.
    const apiKey = KEY_PATTERN.exec(stdout)![0];
    const parsed = parseApiKey(apiKey)!;
    const record = await repositories.credentials.findByKeyId(parsed.keyId);
    expect(record).not.toBeNull();
    expect(JSON.stringify(record)).not.toContain(parsed.secret);
  });

  it("never prints the secret when the store write fails", async () => {
    const failing: CredentialRepository = {
      findByKeyId: async () => null,
      create: async () => {
        throw new Error("insert failed");
      },
      revoke: async () => false,
      revokeAll: async () => 0,
      listByAgent: async () => [],
    };
    const repositories = {
      agents: new InMemoryAgentRepository(),
      credentials: failing,
    };
    const { io, out, err } = capture();

    const code = await runCredentialCli(["create", "--agent", "agent-a"], io, {
      service: new DefaultCredentialService(repositories, new FakeHasher()),
    });

    expect(code).toBe(1);
    expect(out.join("\n")).not.toContain("amcp_");
    expect(err.join("\n")).not.toContain("amcp_");
    // Message only — the raw error object is never dumped.
    expect(err.join("\n")).toContain("insert failed");
  });

  it("requires --agent", async () => {
    const { io, out, err } = capture();
    const code = await runCredentialCli(["create"], io, { service: makeService() });
    expect(code).toBe(1);
    expect(out.join("\n")).not.toContain("amcp_");
    expect(err.join("\n")).toContain("--agent");
  });

  it("rejects an invalid --expires-in-days", async () => {
    const { io, out, err } = capture();
    const code = await runCredentialCli(
      ["create", "--agent", "agent-a", "--expires-in-days", "-1"],
      io,
      { service: makeService() },
    );
    expect(code).toBe(1);
    expect(out.join("\n")).not.toContain("amcp_");
    expect(err.join("\n")).toContain("expires-in-days");
  });
});

describe("runCredentialCli revoke / list", () => {
  it("revokes and lists public key ids only", async () => {
    const repositories = buildInMemoryRepositories();
    const service = makeService(repositories);
    const created = await service.create({ agentId: "agent-a" });

    const revokeCapture = capture();
    const revokeCode = await runCredentialCli(
      ["revoke", "--key-id", created.keyId],
      revokeCapture.io,
      { service },
    );
    expect(revokeCode).toBe(0);
    expect(revokeCapture.out.join("\n")).toContain(created.keyId);
    expect(revokeCapture.out.join("\n")).not.toContain("amcp_");

    const listCapture = capture();
    const listCode = await runCredentialCli(["list", "--agent", "agent-a"], listCapture.io, {
      service,
    });
    expect(listCode).toBe(0);
    const listed = listCapture.out.join("\n");
    expect(listed).toContain(created.keyId);
    expect(listed).toContain("revoked");
    expect(listed).not.toContain("amcp_");
    expect(listed).not.toContain(parseApiKey(created.apiKey)!.secret);
  });

  it("reports an unknown key id without leaking anything", async () => {
    const { io, out, err } = capture();
    const code = await runCredentialCli(["revoke", "--key-id", "deadbeef"], io, {
      service: makeService(),
    });
    expect(code).toBe(1);
    expect(out.join("\n")).not.toContain("amcp_");
    expect(err.join("\n")).toContain("deadbeef");
  });
});

describe("runCredentialCli usage", () => {
  it("prints usage and exits 0 with no arguments", async () => {
    const { io, out } = capture();
    const code = await runCredentialCli([], io, { service: makeService() });
    expect(code).toBe(0);
    expect(out.join("\n")).toContain("AegisMCP credential administration");
    expect(out.join("\n")).not.toContain("amcp_");
  });

  it("rejects an unknown command", async () => {
    const { io, out, err } = capture();
    const code = await runCredentialCli(["frobnicate"], io, { service: makeService() });
    expect(code).toBe(1);
    expect(err.join("\n")).toContain("Unknown command");
    expect(out.join("\n")).not.toContain("amcp_");
  });

  it("supports --help", async () => {
    const { io, out } = capture();
    const code = await runCredentialCli(["--help"], io, { service: makeService() });
    expect(code).toBe(0);
    expect(out.join("\n")).toContain("Usage:");
  });
});
