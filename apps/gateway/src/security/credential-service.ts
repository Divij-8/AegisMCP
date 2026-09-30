/**
 * Credential lifecycle service — creation, revocation, and listing.
 *
 * Used by the operator CLI and by integration tests. Rotation is a two-step
 * operation on top of this: create() a new credential, deploy it, then
 * revoke() the old one.
 *
 * Security notes:
 * - The plaintext API key is returned exactly once from create() and is never
 *   stored. Callers must not persist, log, or include it in error output.
 * - Summaries intentionally omit secretHash and salt.
 */

import type { AgentIdentity } from "./identity.js";
import type { Repositories } from "../repositories/types.js";
import type { SecretHasher } from "./hash.js";
import { formatApiKey, generateKeyId, generateSecret } from "./credential.js";

/** One-time result of credential creation. apiKey is shown once and never stored. */
export interface CreatedCredential {
  readonly keyId: string;
  /** Plaintext API key. Never log or persist this value. */
  readonly apiKey: string;
  readonly agent: AgentIdentity;
  readonly expiresAt: number | null;
}

/** Non-sensitive view of a stored credential. Contains no secret material. */
export interface CredentialSummary {
  readonly keyId: string;
  readonly agentId: string;
  readonly label: string | undefined;
  readonly createdAt: number;
  readonly expiresAt: number | null;
  readonly revokedAt: number | null;
  /** True when the credential is neither revoked nor expired. */
  readonly active: boolean;
}

export interface CreateCredentialInput {
  readonly agentId: string;
  /** Display name to create the agent with if it does not exist yet. */
  readonly agentName?: string;
  readonly label?: string;
  /** Epoch millis, or null/omitted for a non-expiring credential. */
  readonly expiresAt?: number | null;
}

export interface CredentialService {
  create(input: CreateCredentialInput): Promise<CreatedCredential>;
  /** Soft-revoke a credential. Returns true when an active row was revoked. */
  revoke(keyId: string, revokedAt?: number): Promise<boolean>;
  listByAgent(agentId: string): Promise<readonly CredentialSummary[]>;
}

type CredentialRepositories = Pick<Repositories, "agents" | "credentials">;

export class DefaultCredentialService implements CredentialService {
  constructor(
    private readonly repositories: CredentialRepositories,
    private readonly hasher: SecretHasher,
    private readonly now: () => number = Date.now,
  ) {}

  async create(input: CreateCredentialInput): Promise<CreatedCredential> {
    // The agents registry is the source of truth for identity. When the agent
    // already exists we keep its registered name; otherwise we register it.
    const existing = await this.repositories.agents.findById(input.agentId);
    let agent: AgentIdentity;
    if (existing !== null) {
      agent = existing;
    } else {
      agent = Object.freeze({ id: input.agentId, name: input.agentName ?? input.agentId });
      await this.repositories.agents.upsert(agent);
    }

    const keyId = generateKeyId();
    const secret = generateSecret();
    const salt = this.hasher.generateSalt();
    const secretHash = await this.hasher.hash(secret, salt);
    const createdAt = this.now();
    const expiresAt = input.expiresAt ?? null;

    await this.repositories.credentials.create({
      keyId,
      agent,
      secretHash,
      salt,
      hashAlgo: this.hasher.algorithm,
      createdAt,
      expiresAt,
      ...(input.label !== undefined ? { label: input.label } : {}),
    });

    return { keyId, apiKey: formatApiKey(keyId, secret), agent, expiresAt };
  }

  async revoke(keyId: string, revokedAt?: number): Promise<boolean> {
    return this.repositories.credentials.revoke(keyId, revokedAt ?? this.now());
  }

  async listByAgent(agentId: string): Promise<readonly CredentialSummary[]> {
    const records = await this.repositories.credentials.listByAgent(agentId);
    const now = this.now();
    return records.map((record) => ({
      keyId: record.keyId,
      agentId: record.agent.id,
      label: record.label,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
      revokedAt: record.revokedAt,
      active: record.revokedAt === null && (record.expiresAt === null || record.expiresAt > now),
    }));
  }
}
