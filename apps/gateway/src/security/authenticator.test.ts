import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { DbAgentAuthenticator, StaticIdentityAuthenticator } from "./authenticator.js";
import type { SecretHasher } from "./hash.js";
import { formatApiKey, generateKeyId, generateSecret } from "./credential.js";
import { InMemoryCredentialRepository } from "../repositories/memory.js";
import type { CredentialRepository } from "../repositories/types.js";
import type { AgentIdentity } from "./identity.js";

const agent: AgentIdentity = { id: "agent-1", name: "Agent One" };

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

const hasher = new FakeHasher();
const NOW = 1_000;

async function seed(
  repository: InMemoryCredentialRepository,
  options: {
    keyId: string;
    secret: string;
    revokedAt?: number | null;
    expiresAt?: number | null;
    hashAlgo?: string;
  },
): Promise<void> {
  const salt = "fakesalt";
  await repository.create({
    keyId: options.keyId,
    agent,
    secretHash: await hasher.hash(options.secret, salt),
    salt,
    hashAlgo: options.hashAlgo ?? hasher.algorithm,
    createdAt: 0,
    expiresAt: options.expiresAt ?? null,
  });
  if (options.revokedAt != null) {
    await repository.revoke(options.keyId, options.revokedAt);
  }
}

function authenticator(repository: CredentialRepository): DbAgentAuthenticator {
  return new DbAgentAuthenticator(repository, hasher, () => NOW);
}

describe("DbAgentAuthenticator", () => {
  it("accepts a valid credential and resolves the registry agent", async () => {
    const repository = new InMemoryCredentialRepository();
    const keyId = generateKeyId();
    const secret = generateSecret();
    await seed(repository, { keyId, secret });

    const result = await authenticator(repository).authenticate(formatApiKey(keyId, secret));

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.credential.agent).toEqual(agent);
      expect(result.credential.keyId).toBe(keyId);
    }
  });

  it("classifies a missing credential (undefined)", async () => {
    const result = await authenticator(new InMemoryCredentialRepository()).authenticate(undefined);
    expect(result).toEqual({ ok: false, reason: "missing", keyId: null });
  });

  it("classifies an empty credential as missing", async () => {
    const result = await authenticator(new InMemoryCredentialRepository()).authenticate("");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("missing");
  });

  it("classifies a malformed credential without echoing it", async () => {
    const presented = "not-a-real-key";
    const result = await authenticator(new InMemoryCredentialRepository()).authenticate(presented);
    expect(result).toEqual({ ok: false, reason: "malformed", keyId: null });
    expect(JSON.stringify(result)).not.toContain(presented);
  });

  it("classifies an unknown key id", async () => {
    const keyId = generateKeyId();
    const result = await authenticator(new InMemoryCredentialRepository()).authenticate(
      formatApiKey(keyId, generateSecret()),
    );
    expect(result).toEqual({ ok: false, reason: "unknown", keyId });
  });

  it("classifies a revoked credential", async () => {
    const repository = new InMemoryCredentialRepository();
    const keyId = generateKeyId();
    const secret = generateSecret();
    await seed(repository, { keyId, secret, revokedAt: 500 });

    const result = await authenticator(repository).authenticate(formatApiKey(keyId, secret));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("revoked");
      expect(result.keyId).toBe(keyId);
    }
  });

  it("classifies an expired credential", async () => {
    const repository = new InMemoryCredentialRepository();
    const keyId = generateKeyId();
    const secret = generateSecret();
    await seed(repository, { keyId, secret, expiresAt: NOW - 1 });

    const result = await authenticator(repository).authenticate(formatApiKey(keyId, secret));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("expired");
  });

  it("accepts a credential that has not expired yet", async () => {
    const repository = new InMemoryCredentialRepository();
    const keyId = generateKeyId();
    const secret = generateSecret();
    await seed(repository, { keyId, secret, expiresAt: NOW + 1 });

    const result = await authenticator(repository).authenticate(formatApiKey(keyId, secret));
    expect(result.ok).toBe(true);
  });

  it("classifies a wrong secret for a known key id", async () => {
    const repository = new InMemoryCredentialRepository();
    const keyId = generateKeyId();
    await seed(repository, { keyId, secret: generateSecret() });

    const wrongSecret = generateSecret();
    const result = await authenticator(repository).authenticate(formatApiKey(keyId, wrongSecret));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("invalid");
    expect(JSON.stringify(result)).not.toContain(wrongSecret);
  });

  it("refuses a credential whose stored algorithm is unknown", async () => {
    const repository = new InMemoryCredentialRepository();
    const keyId = generateKeyId();
    const secret = generateSecret();
    await seed(repository, { keyId, secret, hashAlgo: "argon2-v1" });

    const result = await authenticator(repository).authenticate(formatApiKey(keyId, secret));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("invalid");
  });

  it("fails closed when the credential store throws", async () => {
    const repository = new InMemoryCredentialRepository();
    const throwing: CredentialRepository = {
      findByKeyId: async () => {
        throw new Error("database unavailable");
      },
      create: (credential) => repository.create(credential),
      revoke: (keyId, revokedAt) => repository.revoke(keyId, revokedAt),
      listByAgent: (agentId) => repository.listByAgent(agentId),
    };

    const keyId = generateKeyId();
    const secret = generateSecret();
    const result = await authenticator(throwing).authenticate(formatApiKey(keyId, secret));

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("error");
      expect(result.keyId).toBe(keyId);
    }
    // The secret never appears in the failure result.
    expect(JSON.stringify(result)).not.toContain(secret);
  });

  it("reports enforced = true", () => {
    expect(authenticator(new InMemoryCredentialRepository()).enforced).toBe(true);
  });
});

describe("StaticIdentityAuthenticator", () => {
  it("is non-enforcing and always returns the configured identity", async () => {
    const staticAuthenticator = new StaticIdentityAuthenticator(agent);
    expect(staticAuthenticator.enforced).toBe(false);

    const result = await staticAuthenticator.authenticate(undefined);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.credential.agent).toEqual(agent);

    const withJunk = await staticAuthenticator.authenticate("garbage");
    expect(withJunk.ok).toBe(true);
  });
});
