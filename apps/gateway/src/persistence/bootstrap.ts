/**
 * Startup bootstrap — the ONLY place that owns persistence lifecycle.
 *
 * With DATABASE_URL set:
 *   1. run forward-only migrations (fail-closed: throw on failure)
 *   2. upsert trusted identity (agent + server) so audit FKs resolve
 *   3. seed policies from initialPolicies into the repository (first boot
 *      convenience; existing DB rows win on later boots via enabled=true
 *      upsert of the same ids)
 *   4. build a PolicyStore whose snapshot is reloadable from PostgreSQL
 *   5. build a BufferedAuditSink (non-blocking, batched, counters)
 *
 * Without DATABASE_URL: no persistence, no audit — exactly pre-Phase-4
 * behavior, with static policies served directly.
 */

import type { Pool } from "pg";
import { createDbPool, disposeDbPool } from "../db/client.js";
import { runMigrations } from "../db/migrate.js";
import { buildPgRepositories } from "../repositories/pg.js";
import type { Repositories } from "../repositories/types.js";
import { PolicyStore } from "../policy/store.js";
import { BufferedAuditSink } from "../audit/sink.js";
import type { AuditSink } from "../audit/types.js";
import type { Policy } from "../policy/types.js";
import type { TrustedIdentityConfig } from "../security/identity.js";

export interface PersistenceOptions {
  readonly databaseUrl: string;
  /** Batch/queue tuning forwarded to the audit sink. */
  readonly audit?: {
    readonly maxQueueSize?: number;
    readonly batchSize?: number;
    readonly flushIntervalMs?: number;
    readonly maxAttempts?: number;
  };
}

export interface Persistence {
  readonly pool: Pool;
  readonly repositories: Repositories;
  readonly policyStore: PolicyStore;
  readonly auditSink: AuditSink;
  /** Trusted identity this gateway is registered under (audit FK anchor). */
  readonly identity: TrustedIdentityConfig;
  dispose(): Promise<void>;
}

export async function initPersistence(
  options: PersistenceOptions,
  identity: TrustedIdentityConfig,
  initialPolicies: readonly Policy[],
): Promise<Persistence> {
  const pool = createDbPool(options.databaseUrl);

  try {
    await runMigrations(pool);
  } catch (err) {
    await disposeDbPool(pool);
    throw err;
  }

  const repositories = buildPgRepositories(pool);

  // Audit FK targets must exist before any event is written.
  await repositories.agents.upsert(identity.agent);
  await repositories.servers.upsert(identity.server);

  // Seed configured policies so a fresh database boots with the intended
  // policy set. Upsert + explicit re-enable: the serving set is exactly the
  // configured set (leftover disabled rows from prior runs don't linger).
  for (const policy of initialPolicies) {
    await repositories.policies.upsert(policy);
    await repositories.policies.setEnabled(policy.id, true);
  }

  const policyStore = new PolicyStore(repositories.policies, initialPolicies);
  await policyStore.reload(); // fail-closed at startup: throw on DB/validation errors

  const auditSink = new BufferedAuditSink(repositories.auditEvents, {
    maxQueueSize: options.audit?.maxQueueSize,
    batchSize: options.audit?.batchSize,
    flushIntervalMs: options.audit?.flushIntervalMs,
    maxAttempts: options.audit?.maxAttempts,
  });

  return {
    pool,
    repositories,
    policyStore,
    auditSink,
    identity,
    dispose: async () => {
      await auditSink.close();
      await disposeDbPool(pool);
    },
  };
}
