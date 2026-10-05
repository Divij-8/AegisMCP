# AegisMCP Threat Model

Scope: the AegisMCP gateway (data plane `/mcp`, control plane `/admin`), its
PostgreSQL store, and its relationship to agents and upstream MCP servers.

## Assets

| Asset | Where | Why it matters |
|-------|-------|----------------|
| Agent credentials | `agent_credentials` (hashes), agent memory (secrets) | Authenticate every request |
| Agent identities | `agents` | Authorization + audit attribution |
| Policies | `policies` | Define what may execute |
| Approval decisions | `approvals` | Grant one-time execution of sensitive tools |
| Audit logs | `audit_events` | Detection, forensics, non-repudiation |
| Upstream MCP capabilities | upstream servers | Real-world side effects |
| Administrative APIs | `/admin` | Change policy, decide approvals, revoke agents |
| Server-side pepper | process environment | Defense-in-depth for credential hashes |

## Threat actors

- **Malicious agent** — a legitimate but hostile client of the gateway.
- **Compromised agent** — a trusted client whose credentials leaked.
- **Malicious / compromised MCP server** — hostile upstream.
- **Unauthorized administrator** — an actor seeking control-plane access.
- **Credential thief** — obtained an API key or database dump.
- **Replay attacker** — captures and replays requests or approvals.
- **Network attacker** — intercepts or alters traffic.

## Threats and mitigations

### 1. Credential theft

- **Attack:** steal an API key from logs, the database, or the wire.
- **Mitigations:** only scrypt hashes + per-credential salts are stored; secrets
  are shown once by the CLI and never logged or audited; auth failure messages
  are generic to avoid an enumeration oracle; optional server-side pepper; TLS at
  the edge; soft revocation via `revoked_at`.
- **Remaining risk:** a key captured in transit before TLS, or a compromised
  client host, can be used until revoked.
- **Planned:** credential expiry enforcement in provisioning defaults, automated
  rotation, anomaly detection on key usage.

### 2. Privilege escalation (agent → administrator)

- **Attack:** an ordinary agent calls `/admin` to change policy or approve its own
  request.
- **Mitigations:** control plane requires enforced authentication; permissions are
  role-based; `AGENT` has zero control-plane permissions; roles are re-read from
  the registry on every admin request; the control plane refuses to operate when
  authentication is not enforced; every denial is audited.
- **Remaining risk:** an `ADMIN`/`OPERATOR` credential is a high-value target and
  is the intended path to privilege.
- **Planned:** optional IP allow-listing and step-up auth for the control plane.

### 3. Tool abuse

- **Attack:** an agent invokes a destructive tool it is allowed to reach.
- **Mitigations:** default-deny policy; explicit ALLOW policies; REQUIRE_APPROVAL
  for sensitive tools; risk engine escalates destructive/shell/infra/database
  patterns; argument constraints narrow ALLOW rules.
- **Remaining risk:** risk detection is name-heuristic and can miss novel tool
  names; a broad ALLOW policy with no constraints is permissive.
- **Planned:** tool-descriptor-derived schemas and capability tags.

### 4. Policy bypass

- **Attack:** craft a request that matches a permissive policy while intending a
  denied action; exploit argument handling or precedence.
- **Mitigations:** severity resolution after matching (`DENY` cannot be
  overridden by priority or arguments); matching is exact and AND-combined; a
  constraint with neither operator fails closed; malformed policies refuse
  startup; policy reload validates before swapping the snapshot.
- **Remaining risk:** a misconfigured broad ALLOW is a policy bug, not a
  mechanism bug; operators must review policy changes.
- **Planned:** policy linting/impact analysis ("what would this ALLOW change?").

### 5. Approval replay

- **Attack:** reuse an approval id for a second execution, or a different request.
- **Mitigations:** approvals are bound to
  `(agent, server, method, tool, argument-hash)`; consumption is a single atomic
  conditional update; replays return `already_consumed`; expired approvals can
  neither be approved nor executed; a request with a different argument set fails
  binding.
- **Remaining risk:** none identified in the transition logic; covered by tests.
- **Planned:** approval IDs are opaque 128-bit random values (already) and never
  sequential.

### 6. Audit tampering / loss

- **Attack:** disable auditing to act without a trace, or flood it to drop events.
- **Mitigations:** audit is append-only via the application; drops are counted and
  exposed (`aegis_audit_dropped`, queue depth); security decisions remain
  fail-closed even when audit is degraded; auth/policy/approval events carry
  identities and request ids.
- **Remaining risk:** a database-level attacker with write access can alter rows;
  audit delivery is fail-open under pressure.
- **Planned:** optional external/WORM audit export and hash-chaining.

### 7. Request spoofing

- **Attack:** claim another agent's identity in the request body or headers.
- **Mitigations:** the gateway ignores client-supplied identity; the
  authenticated credential supplies `agent`, and the configured server identity
  supplies `server`.
- **Remaining risk:** none identified.
- **Planned:** mTLS-bound agent identity.

### 8. Server impersonation

- **Attack:** point the gateway at a hostile upstream.
- **Mitigations:** upstream URL is trusted configuration, never client-supplied.
- **Remaining risk:** a compromised operator can repoint the upstream.
- **Planned:** upstream identity pinning.

### 9. Malicious arguments

- **Attack:** oversized or malformed JSON-RPC/arguments to crash or smuggle
  behavior.
- **Mitigations:** request body and tool-argument size limits; strict JSON-RPC
  parsing with normalization errors; unsupported protocol versions rejected;
  arguments are redacted before use in approvals/audit; downstream tools receive
  the original bytes only after a positive decision.
- **Remaining risk:** upstream servers must still validate their own inputs.
- **Planned:** JSON-schema validation of arguments against tool descriptors.

### 10. Denial of service

- **Attack:** flood the gateway to exhaust CPU/database/upstream.
- **Mitigations:** bounded request body/argument sizes; scrypt verification cost;
  buffered audit that never backpressures requests; connection pool limits;
  upstream timeouts and cancellation.
- **Remaining risk:** rate limiting is delegated to the deployment edge; scrypt is
  CPU-intensive by design.
- **Planned:** in-process per-key rate limiting and request concurrency caps.

## Trust boundaries

```
[untrusted: agents] → TLS edge → [gateway: auth/policy/risk/approval] → [trusted: upstream]
                                        ↓ (private network)
                                 [PostgreSQL: persistence + audit]
```

- **Agents are untrusted** for identity and intent.
- **Upstream is semi-trusted**: reached only after a positive decision.
- **PostgreSQL is trusted** for integrity; protect it accordingly.
- **The operations CLI is trusted** (it holds database access) and is an
  out-of-band admin path, not an untrusted interface.

## Residual risks (summary)

The threats above each list a specific remaining risk. Consolidated, the
material residual risks at the current revision are:

1. **Deployment-edge dependencies.** Rate limiting, TLS termination, and network
   restriction of the control plane are delegated to the deployment edge. An
   unhardened edge weakens every guarantee that assumes a bounded, encrypted
   request stream.
2. **Human/operator error.** Broad `ALLOW` policies, a weak or reused
   `CREDENTIAL_PEPPER`, or an over-privileged `OPERATOR`/`ADMIN` credential are
   the most likely paths to a bad outcome. The mechanism is fail-closed; the
   configuration is not automatically safe.
3. **Trusted-store integrity.** PostgreSQL and the operations CLI are trusted.
   An actor with database write access can alter policies and audit rows; audit
   is append-only **by application convention**, not by database-enforced
   immutability or hash-chaining.
4. **Heuristic detection.** The risk engine recognises destructive/shell/infra/
   database patterns by name; it can miss novel tool names. It only strengthens
   decisions, so this is a gap in *automatic* escalation, not a bypass.
5. **Audit delivery is fail-open.** Under database pressure audit events are
   dropped (counted, never blocking the request). Detect-and-alert is required
   for the audit trail to be trustworthy.
6. **No third-party service integration.** There is no external SIEM/WORM
   export, no managed secrets backend, and no in-process rate limiter. Each is a
   roadmap item, deliberately not implemented here to avoid dependency and
   blast-radius expansion.

## Security regression suite

Every invariant and mitigation above is covered by adversarial tests under
`tests/security/`, runnable with `pnpm run verify`. They exercise the real
gateway over HTTP against PostgreSQL — authentication bypass, policy
precedence, risk escalation, approval binding/replay/expiry/concurrency, RBAC
privilege escalation, redaction, and malformed/oversized input.
