# Security Policy

AegisMCP is a security boundary between AI agents and MCP tool servers. We take
vulnerability reports seriously.

## Reporting a vulnerability

Do **not** open a public issue for a security vulnerability. Report privately to
the maintainers (security contact in repository metadata) with:

- a description and impact assessment,
- reproduction steps or a proof of concept,
- the affected version/commit,
- any suggested mitigation.

We aim to acknowledge reports within a few business days and to coordinate
disclosure after a fix is available.

## Supported versions

The `main` branch is the supported line. Security fixes are applied there first.

## Security invariants

These are non-negotiable properties of the system. A change that weakens any of
them is a security regression and requires explicit review:

1. **Fail closed.** No matching policy denies. Unavailable approval storage
   blocks. Credential-store errors reject. Invalid configuration refuses startup.
2. **No authentication bypass.** `AUTH_REQUIRED=true` requires `DATABASE_URL`
   and enforces credentials on every request. The control plane refuses to run
   when authentication is not enforced.
3. **Decision precedence is fixed.** `DENY > REQUIRE_APPROVAL > ALLOW`. Neither
   priority nor argument constraints can override it.
4. **Risk only strengthens.** The risk engine can never turn a DENY into an
   ALLOW.
5. **Pending never executes.** An approval must be `APPROVED`, unexpired,
   unconsumed, and bound to the exact request before it authorizes execution.
6. **Approvals are single-use.** Consumption is an atomic transition; replays are
   refused.
7. **No secret persistence.** Plaintext credential secrets are never stored,
   logged, or audited. Only scrypt hashes and salts persist.
8. **Redaction.** Tool arguments are redacted before persistence or display;
   secret-looking keys are never stored.
9. **Trusted identity.** Agent identity always comes from the authenticated
   credential, never from the request body.

## Secure deployment checklist

- Set `AUTH_REQUIRED=true` and provide `DATABASE_URL`.
- Set a strong, immutable `CREDENTIAL_PEPPER` and store it as a secret.
- Terminate TLS at the edge; never expose the gateway over plaintext.
- Keep PostgreSQL private; the gateway only needs egress to it and the upstream.
- Run the gateway as a non-root user (the provided image does).
- Restrict the control-plane surface with network policy or an authenticating
  reverse proxy; it is authenticated and authorized but still administrative.
- Back up `agents`, `mcp_servers`, `policies`, and `agent_credentials`; treat
  `audit_events` as append-only.
- Monitor `/metrics` for `aegis_mcp_auth_failures_total`,
  `aegis_admin_auth_failures_total`, upstream errors, and audit queue depth.
- Plan credential rotation (create → deploy → revoke) and approval TTLs to match
  your operational cadence.

## Residual risks

These are known, accepted limitations of the current design. They are tracked
here so operators can compensate at the deployment edge; they are not
vulnerabilities in the invariants above.

| Risk | Impact | Current mitigation | Recommended compensation |
|------|--------|--------------------|--------------------------|
| **No in-process rate limiting** | A flooded gateway consumes CPU (scrypt), connections, and database pool | Bounded body/argument sizes, upstream timeouts, connection-pool limits | Rate limit at the ingress/proxy; add per-key limits (roadmap) |
| **Fail-open audit** | A dropped audit event is not recorded | Drops are counted and surfaced (`aegis_audit_dropped`, queue depth in `/metrics`); security decisions stay fail-closed | Alert on drop/queue-depth metrics; export audit to an append-only store (roadmap) |
| **Heuristic risk engine** | Name-pattern scoring can miss a novel destructive tool name | It only ever *strengthens* a decision; explicit policy is authoritative | Author explicit `REQUIRE_APPROVAL`/`DENY` policies for sensitive tools |
| **Broad `ALLOW` policies are permissive** | A misconfigured ALLOW with no argument constraints grants broad access | Argument constraints narrow ALLOW; DENY cannot be overridden | Review policy diffs; policy linting is roadmap |
| **Credential lifetime** | A leaked key is usable until revoked | Secrets stored only as scrypt hashes; soft revocation via `revoked_at` | Rotate on a schedule (create → deploy → revoke); set expiry in provisioning defaults (roadmap) |
| **Trusted upstream** | A repointed/compromised upstream is trusted | Upstream URL is trusted configuration, never client-supplied | Pin upstream identity/mTLS (roadmap); restrict who can change configuration |
| **Plaintext transport if misconfigured** | Credentials are exposed on the wire | None in-process | Always terminate TLS at the edge; never expose plaintext |
| **Aggregate-only metrics** | No per-request tracing/correlation | Request ids are audited; counters/gauges exposed | Bridge metrics to Prometheus/OTel (roadmap) |
| **`AUTH_REQUIRED=false` compatibility mode** | The gateway accepts any caller and trusts a static identity | Startup refuses `AUTH_REQUIRED=true` without a database; invalid values fail closed | Never use in production; require `AUTH_REQUIRED=true` in any hardened deployment |

## Audit failure behavior

Audit delivery is **fail-open by design**: the request path never blocks on a
database write, and a dropped audit event does not retroactively deny a request
that policy already allowed. Fail-open is bounded: drops are counted
(`aegis_audit_dropped`, audit queue depth in `/metrics`) and must be alerted on.
Authentication, policy, and approval decisions themselves remain fail-closed.
