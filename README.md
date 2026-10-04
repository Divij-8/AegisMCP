# AegisMCP

A zero-trust security gateway for AI-agent tool execution.

AegisMCP sits between AI agents and upstream MCP servers. Every request is
authenticated, normalized into a security context, evaluated against policy,
scored for risk, and then either **executed**, **denied**, or **held for human
approval**. Nothing reaches an upstream MCP server without a positive,
auditable decision.

```
Agent → Aegis Gateway → Authentication → Policy → Risk → Approval → Upstream MCP
```

## Why it exists

Giving an autonomous agent a credential to a tool server is effectively giving it
that tool. AegisMCP makes the tool boundary explicit and enforceable:

- **Fail-closed everything.** No policy match denies. An unavailable approval
  store blocks. A credential-store error rejects. An invalid config refuses
  startup.
- **Trusted identity.** The gateway never trusts an agent-supplied identity; it
  resolves the authenticated principal from its own credential store.
- **Human-in-the-loop.** Destructive operations can require a signed-off
  approval that is bound to the exact request and usable exactly once.
- **Auditable by construction.** Authentication, policy, approval, and execution
  outcomes are recorded without ever persisting secrets.

## Repository layout

```
apps/
  gateway/          Fastify HTTP gateway (data plane + control plane)
  mock-mcp-server/  Reference upstream MCP server for tests/demos
packages/
  protocol/         Shared protocol constants
tests/
  integration/      Cross-package end-to-end suites (PostgreSQL-backed)
```

## Architecture

```mermaid
flowchart LR
  A[Agent] -->|JSON-RPC + credential| G[Aegis Gateway]
  G --> Auth{Authentication}
  Auth -->|fail| R1[401 / 503]
  Auth -->|ok| Parse[Parse → SecurityContext]
  Parse --> Policy{Policy Engine}
  Policy -->|DENY| R2[-32003 blocked]
  Policy --> Risk{Risk Engine}
  Risk -->|escalate| Decide{Final decision}
  Policy --> Decide
  Decide -->|ALLOW| Proxy[Proxy to upstream]
  Decide -->|REQUIRE_APPROVAL| Approve[Create PENDING approval]
  Decide -->|DENY| R3[blocked]
  Approve -->|admin approves| Exec[Agent retries with approval id]
  Exec --> Consume{Consume exactly once}
  Consume -->|ok| Proxy
  Consume -->|no| R4[blocked]
  Proxy --> U[Upstream MCP server]
  G --> Audit[(Buffered audit → PostgreSQL)]
```

### Components

| Component | Location | Responsibility |
|-----------|----------|----------------|
| MCP normalization | `apps/gateway/src/mcp` | JSON-RPC parsing → `SecurityContext` |
| Authentication | `apps/gateway/src/security` | scrypt credential verification, roles/RBAC |
| Policy engine | `apps/gateway/src/policy` | deterministic ALLOW/DENY/REQUIRE_APPROVAL |
| Risk engine | `apps/gateway/src/risk` | escalate-only risk scoring |
| Approvals | `apps/gateway/src/approvals` | human approval lifecycle + redaction |
| Control plane | `apps/gateway/src/routes/admin.ts` | administrative API |
| Persistence | `apps/gateway/src/repositories` | agent/server/policy/audit/approval storage |
| Audit | `apps/gateway/src/audit` | non-blocking, batched, redacted audit trail |

## Security model

- **Decision precedence is fixed:** `DENY > REQUIRE_APPROVAL > ALLOW`. Priority
  and matching never override severity.
- **Risk can only strengthen:** a risk score can escalate ALLOW to
  REQUIRE_APPROVAL or DENY, but never weakens a DENY.
- **Approvals are bound and single-use:** an approval is tied to the exact
  `(agent, server, method, tool, argument-hash)` and consumed atomically.
- **Least privilege by default:** the static/dev identity is `AGENT` (no
  control-plane permissions), and the control plane refuses to operate unless
  credential authentication is actually enforced.
- **Secrets never persist:** plaintext API keys are shown once; only scrypt
  hashes and per-credential salts are stored. Approval arguments are redacted;
  audit rows never contain raw arguments.

See [`SECURITY.md`](SECURITY.md) and [`docs/threat-model.md`](docs/threat-model.md).

## Authentication

Credentials are bearer API keys in the form `amcp_<keyId>_<secret>`:

- `keyId` — 16 random bytes, hex. A **public** lookup id, safe to store and audit.
- `secret` — 32 random bytes, hex. **Secret.** Only an scrypt hash is stored.

Present the key as `Authorization: Bearer <key>` or `X-API-Key: <key>`.
Set `AUTH_REQUIRED=true` together with `DATABASE_URL` to enforce authentication
(the gateway refuses to start if `AUTH_REQUIRED=true` without a database).

Create credentials with the CLI:

```bash
pnpm --filter @aegis/gateway credential:create -- --agent my-agent --role OPERATOR
```

## Policy engine

A policy is pure data: `{ id, decision, match, reason, priority?, enabled? }`.
`match` supports `agent`, `server`, `method`, `tool`, and optional `arguments`
constraints:

```json
{
  "id": "allow-safe-write",
  "decision": "ALLOW",
  "reason": "appending is safe",
  "match": {
    "tool": "file.write",
    "arguments": { "mode": { "equals": "append" } }
  }
}
```

Argument constraints only narrow when an ALLOW/REQUIRE_APPROVAL applies. They can
never carve an exception out of a DENY, because severity is resolved after
matching.

## Approval workflow

```mermaid
sequenceDiagram
  participant A as Agent
  participant G as Aegis
  participant D as Admin
  A->>G: tools/call danger.delete
  G->>G: policy → REQUIRE_APPROVAL
  G->>G: create PENDING approval (redacted args)
  G-->>A: -32002 + { approvalId, expiresAt }
  D->>G: POST /admin/approvals/:id/approve
  G-->>D: APPROVED
  A->>G: same request + X-Aegis-Approval-Id
  G->>G: consume (bound, unexpired, unused)
  G->>G: execute upstream
  G-->>A: result
```

- Pending approvals never execute.
- Expired approvals can neither be approved nor executed.
- Replays are refused: consumption is a single atomic transition.
- A different agent, server, tool, or argument set cannot use the approval.

## Risk engine

Risk scoring runs after policy and can only make the decision stricter. Default
mapping (configurable): `LOW`/`MEDIUM` inherit, `HIGH` → REQUIRE_APPROVAL,
`CRITICAL` → DENY. Disable with `RISK_ENGINE=false`.

## Audit architecture

Audit is a **buffered, non-blocking** sink: `record()` enqueues in memory and a
background timer flushes batches to PostgreSQL. Under pressure the oldest events
are dropped (counted), never the request. On shutdown, `close()` drains.

Event types: `request`, `notification`, `auth`, `admin`, `approval_created`,
`approval_approved`, `approval_denied`, `approval_expired`. Auth failures are
fail-closed; audit delivery is fail-open (a dropped audit event never blocks a
request that policy already allowed) and dropping is surfaced via the
`aegis_audit_dropped`/queue-depth metrics.

## Database architecture

Forward-only SQL migrations in `apps/gateway/src/db/migrations`, applied inside
transactions under an advisory lock. Tables: `agents`, `mcp_servers`,
`policies`, `audit_events`, `agent_credentials`, `approvals`.

## HTTP API

### Data plane

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/mcp` | MCP JSON-RPC endpoint (authenticate → policy → risk → approval/proxy) |
| `GET`  | `/health` | Liveness |
| `GET`  | `/ready` | Readiness (checks the database) |
| `GET`  | `/metrics` | Aggregate counters/gauges (no secrets) |

### Control plane (`/admin`, requires a privileged role)

| Method | Path | Permission |
|--------|------|------------|
| `GET`  | `/admin/approvals` | `approval:read` |
| `GET`  | `/admin/approvals/:id` | `approval:read` |
| `POST` | `/admin/approvals/:id/approve` | `approval:decide` |
| `POST` | `/admin/approvals/:id/deny` | `approval:decide` |
| `GET`  | `/admin/policies` | `policy:read` |
| `GET`  | `/admin/policies/:id` | `policy:read` |
| `POST` | `/admin/policies` | `policy:write` |
| `PATCH`| `/admin/policies/:id` | `policy:write` |
| `DELETE`| `/admin/policies/:id` | `policy:write` |
| `POST` | `/admin/policies/reload` | `policy:write` |
| `GET`  | `/admin/agents` | `agent:read` |
| `GET`  | `/admin/agents/:id` | `agent:read` |
| `POST` | `/admin/agents` | `agent:manage` |
| `POST` | `/admin/agents/:id/revoke` | `agent:manage` |
| `GET`  | `/admin/servers` | `server:read` |
| `GET`  | `/admin/servers/:id` | `server:read` |
| `GET`  | `/admin/audit` | `audit:read` |
| `GET`  | `/admin/audit/:id` | `audit:read` |
| `GET`  | `/admin/me` | any control-plane role |

List endpoints accept `limit` (1–200, default 50) and `offset`, and return
`{ items, total, limit, offset }`. Errors are consistent:
`{ "error": { "code", "message", "requestId" } }`.

### Roles

| Role | Permissions |
|------|-------------|
| `ADMIN` | all |
| `OPERATOR` | read + `approval:decide`, `policy:write`, `agent:manage` |
| `AUDITOR` | read-only |
| `AGENT` | none (data plane only) |

## CLI

```bash
# Credentials
pnpm --filter @aegis/gateway credential:create -- --agent bot --role AGENT
pnpm --filter @aegis/gateway credential:list   -- --agent bot
pnpm --filter @aegis/gateway credential:revoke -- --key-id <keyId>

# Operations (agents, policies, approvals, audit)
pnpm --filter @aegis/gateway operations -- agent create --id ops --role OPERATOR
pnpm --filter @aegis/gateway operations -- policy list
pnpm --filter @aegis/gateway operations -- approval list --status PENDING
pnpm --filter @aegis/gateway operations -- approval approve --id apr_... --reason "reviewed"
pnpm --filter @aegis/gateway operations -- audit list --limit 20
```

CLI output never prints secrets.

## Local setup

```bash
pnpm install

export DATABASE_URL="postgres://aegis:aegis@127.0.0.1:5432/aegis"
pnpm --filter @aegis/gateway db:migrate

# Terminal 1: upstream mock MCP server
pnpm --filter @aegis/mock-mcp-server dev

# Terminal 2: gateway
DATABASE_URL=$DATABASE_URL AUTH_REQUIRED=true pnpm run dev
```

## Environment variables

See [`.env.example`](.env.example). Highlights:

| Variable | Meaning | Default |
|----------|---------|---------|
| `DATABASE_URL` | PostgreSQL connection; enables persistence, policies, audit | unset |
| `AUTH_REQUIRED` | Enforce agent credentials (`true`/`false`) | `false` |
| `CREDENTIAL_PEPPER` | Optional server-side pepper (immutable) | empty |
| `UPSTREAM_URL` / `UPSTREAM_TIMEOUT_MS` | Upstream MCP target/timeout | mock server / 30000 |
| `APPROVAL_TTL_MS` / `APPROVAL_MAX_TTL_MS` | Approval lifetime bounds | 900000 / 86400000 |
| `RISK_ENGINE` | Enable the risk engine | `true` |
| `MAX_REQUEST_BODY_BYTES` / `MAX_TOOL_ARGUMENT_BYTES` | Size limits | 1048576 / 262144 |
| `AGENT_ID` / `AGENT_NAME` / `AGENT_ROLE` | Static identity (dev only) | defaults |

## Running tests

```bash
pnpm run test          # unit + integration (integration needs DATABASE_URL)
pnpm run typecheck
pnpm run lint
pnpm run format:check
pnpm run check         # all of the above in sequence
```

## Docker deployment

```bash
cp .env.example .env    # then edit secrets
docker compose up --build
```

`docker-compose.yml` runs PostgreSQL, the mock upstream, and the gateway (which
migrates on startup). The gateway image runs as a non-root user.

## Threat model

See [`docs/threat-model.md`](docs/threat-model.md) for assets, actors, threats,
existing mitigations, and remaining risk.

## Known limitations

- The risk engine is heuristic (tool-name pattern based); it complements, not
  replaces, explicit policy.
- Policy argument constraints narrow ALLOW/REQUIRE_APPROVAL but cannot create
  exceptions to a DENY (by design).
- The operations CLI is a trusted, out-of-band admin path (it has database
  access); it is not a substitute for the authenticated control plane.
- Metrics are aggregate-only and served in-process (no Prometheus exposition
  format yet).
- Rate limiting is delegated to the deployment edge (ingress/proxy).

## Roadmap

- OpenTelemetry traces across auth → policy → risk → approval → upstream.
- Structured per-request logging with correlation IDs.
- Deny-list/allow-list argument schemas sourced from MCP tool descriptors.
- Native Prometheus exposition and Go/OTel metrics bridge.
- Approval quorum (multi-approver) for CRITICAL operations.

## License

See repository metadata.
