/**
 * Agent authentication — transport-independent.
 *
 * This module knows nothing about Fastify, HTTP, headers, or routing. It takes
 * an already-extracted credential string and returns an identity or a failure
 * reason. Everything here is testable with an in-memory repository and a fake
 * hasher.
 *
 * Invariants:
 * - The presented credential (and its secret) never appears in a result, a
 *   thrown error, or a log line produced by this module.
 * - Every failure is fail-closed: the caller must reject, never fall through.
 */

import type { AgentIdentity } from "./identity.js";
import type { AuthFailureReason } from "../audit/types.js";
import type { CredentialRepository } from "../repositories/types.js";
import type { SecretHasher } from "./hash.js";
import { parseApiKey } from "./credential.js";

/** A successfully authenticated agent. */
export interface AuthenticatedAgent {
  readonly agent: AgentIdentity;
  /** Public key id of the credential that authenticated (safe to record). */
  readonly keyId: string;
}

export type AuthResult =
  | { readonly ok: true; readonly credential: AuthenticatedAgent }
  | {
      readonly ok: false;
      readonly reason: AuthFailureReason;
      /** Public key id when one could be parsed; otherwise null. Never the secret. */
      readonly keyId: string | null;
      /** Underlying infrastructure error, for audit/diagnostics. Never the secret. */
      readonly error?: unknown;
    };

export interface AgentAuthenticator {
  /** True when credentials are actually enforced (vs. static trusted identity). */
  readonly enforced: boolean;
  /** Resolve a presented credential to an agent, or explain the rejection. */
  authenticate(presented: string | undefined): Promise<AuthResult>;
}

/**
 * Non-enforcing authenticator used to preserve pre-Phase-5 behavior when
 * AUTH_REQUIRED is false. It trusts the configured static identity — this is
 * a compatibility/dev mode, NOT an authentication posture.
 */
export class StaticIdentityAuthenticator implements AgentAuthenticator {
  readonly enforced = false;

  constructor(private readonly agent: AgentIdentity) {}

  async authenticate(_presented: string | undefined): Promise<AuthResult> {
    return { ok: true, credential: { agent: this.agent, keyId: "static" } };
  }
}

/**
 * Database-backed authenticator. Enforces credentials on every request:
 * missing, malformed, unknown, revoked, expired, and invalid secrets are all
 * rejected, and any credential-store failure is fail-closed.
 */
export class DbAgentAuthenticator implements AgentAuthenticator {
  readonly enforced = true;

  constructor(
    private readonly repository: CredentialRepository,
    private readonly hasher: SecretHasher,
    private readonly now: () => number = Date.now,
    private readonly onError?: (error: unknown) => void,
  ) {}

  async authenticate(presented: string | undefined): Promise<AuthResult> {
    if (presented === undefined || presented.length === 0) {
      return { ok: false, reason: "missing", keyId: null };
    }

    const parsed = parseApiKey(presented);
    if (parsed === null) {
      // Do not echo the presented value — it may be a mistyped real secret.
      return { ok: false, reason: "malformed", keyId: null };
    }

    let record;
    try {
      record = await this.repository.findByKeyId(parsed.keyId);
    } catch (error) {
      this.onError?.(error);
      return { ok: false, reason: "error", keyId: parsed.keyId, error };
    }

    if (record === null) {
      return { ok: false, reason: "unknown", keyId: parsed.keyId };
    }
    if (record.revokedAt !== null) {
      return { ok: false, reason: "revoked", keyId: parsed.keyId };
    }
    if (record.expiresAt !== null && record.expiresAt <= this.now()) {
      return { ok: false, reason: "expired", keyId: parsed.keyId };
    }
    if (record.hashAlgo !== this.hasher.algorithm) {
      // Unknown algorithm: cannot verify, so refuse rather than guess.
      return { ok: false, reason: "invalid", keyId: parsed.keyId };
    }

    let valid: boolean;
    try {
      valid = await this.hasher.verify(parsed.secret, record.salt, record.secretHash);
    } catch (error) {
      this.onError?.(error);
      return { ok: false, reason: "error", keyId: parsed.keyId, error };
    }

    if (!valid) {
      return { ok: false, reason: "invalid", keyId: parsed.keyId };
    }

    return { ok: true, credential: { agent: record.agent, keyId: parsed.keyId } };
  }
}
