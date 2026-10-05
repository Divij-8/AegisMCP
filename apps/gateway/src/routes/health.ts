import type { FastifyInstance } from "fastify";
import type { Persistence } from "../persistence/bootstrap.js";
import type { Metrics } from "../observability/metrics.js";
import type { AuditSink } from "../audit/types.js";
import type { PolicyStore } from "../policy/store.js";

export interface HealthRoutesOptions {
  readonly metrics: Metrics;
  readonly auditSink: () => AuditSink;
  readonly policyStore: () => PolicyStore;
  readonly getPersistence: () => Persistence | null;
  readonly startedAt: number;
}

export async function healthRoutes(
  fastify: FastifyInstance,
  options: HealthRoutesOptions,
): Promise<void> {
  // Liveness: the process is up and serving. Never touches the database.
  fastify.get("/health", async () => {
    return { status: "ok" };
  });

  // Readiness: dependencies are usable. Fail closed with 503 when the database
  // is configured but unreachable.
  fastify.get("/ready", async (_request, reply) => {
    const persistence = options.getPersistence();
    if (persistence === null) {
      return { status: "ready", persistence: false };
    }
    try {
      await persistence.pool.query("SELECT 1");
      return { status: "ready", persistence: true };
    } catch {
      reply.code(503);
      return { status: "not_ready", persistence: true };
    }
  });

  // Aggregate counters and gauges. Intentionally contains no secrets and no
  // per-request data — only totals.
  fastify.get("/metrics", async () => {
    const persistence = options.getPersistence();
    const snapshot = options.policyStore().getSnapshot();

    let pendingApprovals: number | null = null;
    if (persistence !== null) {
      const page = await persistence.repositories.approvals.list(
        { status: "PENDING" },
        { limit: 1, offset: 0 },
      );
      pendingApprovals = page.total;
    }

    return {
      uptimeSeconds: Math.floor((Date.now() - options.startedAt) / 1000),
      counters: options.metrics.snapshot(),
      audit: options.auditSink().stats(),
      policies: {
        active: snapshot.policies.length,
        loadedAt: snapshot.loadedAt,
      },
      approvals: { pending: pendingApprovals },
    };
  });
}
