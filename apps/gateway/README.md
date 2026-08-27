# @aegis/gateway

AegisMCP policy-enforcing gateway for MCP tool requests.

## Overview

The gateway sits between AI agents and upstream MCP servers. Every `tools/call` request is evaluated against an ordered policy list before being forwarded. Policies are pure data — no executable expressions, no code, no side effects.

Notifications are always forwarded without policy evaluation.

## Default behavior

An empty policy array (`[]`) denies **all** requests. The gateway is fail-closed: no matching policy means DENY.

## Policies

Policies are passed to `buildApp()` via the `policies` option.

```ts
import { buildApp } from "@aegis/gateway/app";

const app = buildApp({
  upstreamUrl: "http://127.0.0.1:3001/mcp",
  policies: [ /* ... */ ],
});
```

Each policy has:

| Field      | Description |
|------------|-------------|
| `id`       | Unique, human-readable identifier |
| `decision` | `ALLOW`, `DENY`, or `REQUIRE_APPROVAL` |
| `match`    | Conditions — all specified fields must match (AND logic). Unspecified fields are wildcards. `{}` matches everything. |
| `reason`   | Human-readable explanation |
| `priority` | Optional numeric priority. Higher wins within the same decision severity. Default: 0. |

## Decision types

### DENY

The request is never forwarded. A JSON-RPC error with code `-32003` is returned.

```ts
{
  id: "deny-delete",
  decision: "DENY",
  match: { tool: "database.delete" },
  reason: "Direct database deletion is forbidden",
}
```

### ALLOW

The request is forwarded to the upstream server unchanged.

```ts
{
  id: "allow-echo",
  decision: "ALLOW",
  match: { tool: "echo" },
  reason: "Echo is a safe diagnostic tool",
}
```

### REQUIRE_APPROVAL

The request is blocked and a JSON-RPC error with code `-32002` is returned. Upstream is never contacted.

**Phase 3 note:** `REQUIRE_APPROVAL` does not yet trigger a human approval workflow. It simply prevents forwarding and returns a structured error. A future phase will add the approval mechanism.

```ts
{
  id: "confirm-destroy",
  decision: "REQUIRE_APPROVAL",
  match: { tool: "system.destroy" },
  reason: "Destructive action requires human approval",
}
```

## Precedence

When multiple policies match a request, the most restrictive decision wins:

**DENY > REQUIRE_APPROVAL > ALLOW**

Priority cannot override this ordering. Within the same decision severity, higher `priority` wins. If severity and priority are both tied, the earlier-declared policy wins.

### Example

```ts
const policies = [
  {
    id: "allow-all",
    decision: "ALLOW",
    match: {},
    reason: "Default allow",
  },
  {
    id: "confirm-destroy",
    decision: "REQUIRE_APPROVAL",
    match: { tool: "system.destroy" },
    reason: "Destructive action",
  },
  {
    id: "deny-nuclear",
    decision: "DENY",
    match: { tool: "system.destroy" },
    reason: "Nuclear option is always forbidden",
  },
];

const app = buildApp({ policies });
```

For `tools/call` with `name: "system.destroy"`, all three policies match. `deny-nuclear` wins (DENY > REQUIRE_APPROVAL > ALLOW).

For `tools/call` with `name: "echo"`, only `allow-all` matches → ALLOW → forwarded to upstream.

For `tools/call` with `name: "database.delete"`, no policy matches → default DENY.

## Match fields

| Field    | Matches against                | Example values |
|----------|--------------------------------|----------------|
| `tool`   | `SecurityContext.toolName`     | `"echo"`, `"database.delete"` |
| `method` | `SecurityContext.method`       | `"tools/call"`, `"tools/list"` |
| `agent`  | `SecurityContext.agent.id`     | `"alpha-agent"` |
| `server` | `SecurityContext.server.id`    | `"mock-server"` |

All specified fields use exact string matching. An empty `match: {}` is a catch-all.

## Error codes

| Code     | Meaning |
|----------|---------|
| `-32002` | REQUIRE_APPROVAL — request blocked, approval required |
| `-32003` | DENY — request blocked by policy |

## JSON-RPC response format

Policy decisions are returned as standard JSON-RPC error responses:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32003,
    "message": "Direct database deletion is forbidden"
  }
}
```
