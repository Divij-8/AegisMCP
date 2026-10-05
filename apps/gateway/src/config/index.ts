import { DEFAULT_UPSTREAM_URL } from "@aegis/protocol";
import { resolveIdentity } from "../security/identity.js";
import type { Policy } from "../policy/types.js";

/**
 * Thrown when an environment value is present but not a recognized value.
 * Configuration errors are fail-closed: the gateway refuses to start rather
 * than silently falling back to a weaker mode.
 */
export class ConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigurationError";
  }
}

/**
 * Decode AUTH_REQUIRED fail-closed.
 *
 * - unset / empty / whitespace-only        → false (opt-in default, compatibility mode)
 * - "true" / "TRUE" / "True"               → true
 * - "false" / "FALSE" / "False"            → false
 * - any other non-empty value              → ConfigurationError
 *
 * The last rule is deliberate: a typo such as AUTH_REQUIRED=TRUE (accepted here)
 * is fine, but an unrecognized value like "yes" or "1" would otherwise decode to
 * "not required" and silently run the gateway unauthenticated. Refusing to start
 * keeps the failure mode closed.
 */
export function parseAuthRequired(raw: string | undefined): boolean {
  if (raw === undefined) return false;

  const normalized = raw.trim().toLowerCase();
  if (normalized === "") return false;
  if (normalized === "true") return true;
  if (normalized === "false") return false;

  throw new ConfigurationError(
    'Invalid AUTH_REQUIRED: expected "true" or "false". Refusing to start rather than ' +
      "silently running with authentication disabled.",
  );
}

export const config = {
  port: Number(process.env.PORT ?? 3000),
  host: process.env.HOST ?? "0.0.0.0",
  upstreamUrl: process.env.UPSTREAM_URL ?? DEFAULT_UPSTREAM_URL,
  upstreamTimeoutMs: Number(process.env.UPSTREAM_TIMEOUT_MS ?? 30_000),
  identity: resolveIdentity(),
  policies: [] as Policy[],
  /**
   * Persistence is opt-in: when DATABASE_URL is set, the gateway migrates
   * (fail-closed) and serves policies from PostgreSQL with a buffered
   * audit sink. Without it, behavior is exactly pre-Phase-4: in-memory
   * policies, no persistence, no audit.
   */
  databaseUrl: process.env.DATABASE_URL,
  /**
   * Authentication enforcement, INDEPENDENT of persistence availability.
   *
   * Raw AUTH_REQUIRED value — decoded by parseAuthRequired at the composition
   * root so an invalid value fails startup instead of silently disabling auth.
   *
   * AUTH_REQUIRED=false is an UNAUTHENTICATED, DEVELOPMENT/COMPATIBILITY MODE.
   * It must never be treated as a production-hardened authentication posture:
   * the gateway trusts a static configured agent identity and accepts any
   * caller. Production deployments must set AUTH_REQUIRED=true together with
   * DATABASE_URL (which is enforced at startup).
   */
  authRequired: process.env.AUTH_REQUIRED,
  /**
   * Optional server-side pepper mixed into credential hashing (defense in
   * depth if the credential table leaks without the application environment).
   *
   * IMMUTABLE: the pepper must remain unchanged for the lifetime of every
   * credential created with it. The pepper is not stored with the credential,
   * so changing it causes every existing credential to stop verifying — a
   * full authentication outage that must be recovered by rotating/recreating
   * credentials. Plan a pepper change together with credential rotation.
   */
  credentialPepper: process.env.CREDENTIAL_PEPPER ?? "",
  /**
   * Approval workflow tuning. TTL is the lifetime of a newly created approval;
   * the max caps any per-request override so an approval can never be made
   * effectively permanent.
   */
  approvalTtlMs: Number(process.env.APPROVAL_TTL_MS ?? 900_000),
  approvalMaxTtlMs: Number(process.env.APPROVAL_MAX_TTL_MS ?? 86_400_000),
  /**
   * Risk engine. Enabled by default; can only strengthen policy decisions.
   * Set RISK_ENGINE=false to disable (e.g. to debug policy in isolation).
   */
  riskEnabled: (process.env.RISK_ENGINE ?? "true").trim().toLowerCase() !== "false",
  /** Maximum accepted MCP request body size, in bytes. */
  maxRequestBodyBytes: Number(process.env.MAX_REQUEST_BODY_BYTES ?? 1_048_576),
  /** Maximum accepted MCP tool-arguments size, in bytes. */
  maxToolArgumentBytes: Number(process.env.MAX_TOOL_ARGUMENT_BYTES ?? 262_144),
} as const;

export type AppConfig = typeof config;
