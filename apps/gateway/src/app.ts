import Fastify from "fastify";
import { config, parseAuthRequired } from "./config/index.js";
import { healthRoutes } from "./routes/health.js";
import { mcpRoutes } from "./routes/mcp.js";
import type { TrustedIdentityConfig } from "./security/identity.js";
import type { Policy } from "./policy/types.js";
import { initPersistence } from "./persistence/bootstrap.js";
import type { Persistence } from "./persistence/bootstrap.js";
import { PolicyStore } from "./policy/store.js";
import { NullAuditSink } from "./audit/null-sink.js";
import type { AuditSink } from "./audit/types.js";
import { DbAgentAuthenticator, StaticIdentityAuthenticator } from "./security/authenticator.js";
import type { AgentAuthenticator } from "./security/authenticator.js";
import { ScryptSecretHasher } from "./security/hash.js";
import { ApprovalService } from "./approvals/service.js";
import { RiskEngine } from "./risk/engine.js";
import { adminRoutes } from "./routes/admin.js";
import { dashboardRoutes } from "./routes/dashboard.js";
import { Metrics } from "./observability/metrics.js";

export interface AppOptions {
  upstreamUrl?: string;
  upstreamTimeoutMs?: number;
  identity?: TrustedIdentityConfig;
  policies?: Policy[];
  /**
   * When set (non-empty string), enables PostgreSQL persistence, DB-backed
   * policies, and audit. Explicit `null` force-disables persistence even if
   * DATABASE_URL is present in the environment (used by tests).
   * `undefined` inherits config (which reads the DATABASE_URL env var).
   */
  databaseUrl?: string | null;
  /** Audit sink tuning, forwarded to BufferedAuditSink. */
  audit?: {
    maxQueueSize?: number;
    batchSize?: number;
    flushIntervalMs?: number;
    maxAttempts?: number;
  };
  /** Risk engine override (tests / specialized deployments). */
  risk?: {
    enabled?: boolean;
    engineOptions?: ConstructorParameters<typeof RiskEngine>[0];
  };
  /** Maximum accepted MCP request body size in bytes (defaults to config). */
  maxRequestBodyBytes?: number;
  /**
   * Authentication enforcement override. `undefined` inherits AUTH_REQUIRED.
   * `true` requires DATABASE_URL (startup fails otherwise) and enforces
   * credentials; `false` runs the unauthenticated compatibility mode.
   */
  auth?: {
    required?: boolean;
  };
}

declare module "fastify" {
  interface FastifyInstance {
    /** Non-null once the server is ready with persistence enabled. */
    persistence: Persistence | null;
  }
}

export function buildApp(options?: AppOptions) {
  const app = Fastify({
    logger: false,
    // Reject oversized bodies at the framework edge, before our content parser.
    bodyLimit: options?.maxRequestBodyBytes ?? config.maxRequestBodyBytes,
  });

  const identity = options?.identity ?? config.identity;
  const staticPolicies = options?.policies ?? config.policies;
  // Empty string counts as unset — CI shells often export empty env vars.
  // Explicit null opts out entirely (test isolation from ambient DATABASE_URL).
  const databaseUrl =
    options?.databaseUrl !== undefined ? options.databaseUrl : config.databaseUrl || undefined;
  const persistenceEnabled = databaseUrl != null && databaseUrl.length > 0;
  // Decoding AUTH_REQUIRED can throw ConfigurationError: fail closed at startup.
  const authRequired = options?.auth?.required ?? parseAuthRequired(config.authRequired);

  // Authentication needs the credential store, which only exists with
  // persistence. Refuse to start rather than silently running unauthenticated.
  if (authRequired && !persistenceEnabled) {
    throw new Error(
      "AUTH_REQUIRED=true requires DATABASE_URL: agent authentication needs the PostgreSQL " +
        "credential store. Set DATABASE_URL, or run with AUTH_REQUIRED=false (unauthenticated " +
        "development/compatibility mode).",
    );
  }

  // Runtime bindings. When persistence is enabled these are swapped by the
  // boot plugin (which completes before listen/inject resolve). The routes
  // receive a shared, mutable holder object — reads at request time always
  // see the live store, so a completed reload affects subsequent requests.
  let policyStore = new PolicyStore(null, staticPolicies);
  let auditSink: AuditSink = new NullAuditSink();
  const staticAuthenticator = new StaticIdentityAuthenticator(identity.agent);
  // Risk engine is optional; when absent the policy decision passes through.
  const riskEngine =
    (options?.risk?.enabled ?? config.riskEnabled)
      ? new RiskEngine(options?.risk?.engineOptions ?? {})
      : undefined;
  // Explicitly widened so the boot plugin can swap in the enforcing authenticator.
  const startedAt = Date.now();
  const metrics = new Metrics();
  const runtime: {
    policyStore: PolicyStore;
    auditSink: AuditSink;
    authenticator: AgentAuthenticator;
    approvalService: ApprovalService;
    riskEngine: RiskEngine | undefined;
    metrics: Metrics;
  } = {
    policyStore,
    auditSink,
    authenticator: staticAuthenticator,
    // Without persistence there is no approval repository: the service is
    // unavailable and REQUIRE_APPROVAL fails closed (never executes).
    approvalService: new ApprovalService(null, auditSink),
    riskEngine,
    metrics,
  };

  app.decorate("persistence", null);

  app.addHook("onReady", async () => {
    if (!persistenceEnabled || databaseUrl == null) return;

    const persistence = await initPersistence(
      { databaseUrl, audit: options?.audit },
      identity,
      staticPolicies,
    );
    policyStore = persistence.policyStore;
    auditSink = persistence.auditSink;
    runtime.policyStore = policyStore;
    runtime.auditSink = auditSink;
    runtime.authenticator = authRequired
      ? new DbAgentAuthenticator(
          persistence.repositories.credentials,
          new ScryptSecretHasher({ pepper: config.credentialPepper }),
        )
      : staticAuthenticator;
    runtime.approvalService = new ApprovalService(persistence.repositories.approvals, auditSink, {
      defaultTtlMs: config.approvalTtlMs,
      maxTtlMs: config.approvalMaxTtlMs,
    });
    app.persistence = persistence;
  });

  app.addHook("onClose", async () => {
    if (app.persistence != null) {
      await app.persistence.dispose();
      app.persistence = null;
    }
  });

  app.register(healthRoutes, {
    metrics,
    auditSink: () => runtime.auditSink,
    policyStore: () => runtime.policyStore,
    getPersistence: () => app.persistence,
    startedAt,
  });
  app.register(mcpRoutes, {
    upstreamUrl: options?.upstreamUrl ?? config.upstreamUrl,
    upstreamTimeoutMs: options?.upstreamTimeoutMs ?? config.upstreamTimeoutMs,
    maxRequestBodyBytes: options?.maxRequestBodyBytes ?? config.maxRequestBodyBytes,
    maxToolArgumentBytes: config.maxToolArgumentBytes,
    identity,
    runtime,
  });
  app.register(adminRoutes, {
    runtime,
    getPersistence: () => app.persistence,
  });
  // Static, secretless browser shell. All data it displays is fetched from the
  // authenticated /admin API by the browser; this route adds no data path.
  app.register(dashboardRoutes);

  return app;
}
