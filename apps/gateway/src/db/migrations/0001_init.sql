-- 0001_init.sql — AegisMCP initial persistence schema (forward-only).
--
-- Design notes:
-- - audit_events intentionally has NO column for raw tool arguments.
--   tool_args_hash / tool_args_hash_algo are reserved for future
--   redaction/hashing and are never populated by the gateway today.
-- - Policies are stored as pure data (JSONB match object) — the same shape
--   PolicyEngine already consumes. enabled=false rows are excluded from loads.

CREATE TABLE IF NOT EXISTS agents (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS mcp_servers (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  upstream_url TEXT NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  enabled      BOOLEAN NOT NULL DEFAULT TRUE,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS policies (
  id         TEXT PRIMARY KEY,
  decision   TEXT NOT NULL CHECK (decision IN ('ALLOW', 'DENY', 'REQUIRE_APPROVAL')),
  match      JSONB NOT NULL,
  reason     TEXT NOT NULL,
  priority   INTEGER NOT NULL DEFAULT 0,
  enabled    BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_events (
  id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_type      TEXT NOT NULL CHECK (event_type IN ('request', 'notification')),
  request_id      TEXT,
  occurred_at     TIMESTAMPTZ NOT NULL,
  agent_id        TEXT NOT NULL REFERENCES agents(id),
  server_id       TEXT NOT NULL REFERENCES mcp_servers(id),
  method          TEXT NOT NULL,
  tool_name       TEXT,
  decision        TEXT CHECK (decision IN ('ALLOW', 'DENY', 'REQUIRE_APPROVAL')),
  policy_id       TEXT,
  reason          TEXT NOT NULL,
  outcome         TEXT NOT NULL CHECK (outcome IN ('blocked', 'forwarded', 'upstream_error')),
  upstream_status INTEGER,
  latency_ms      INTEGER NOT NULL CHECK (latency_ms >= 0),
  tool_args_hash      TEXT,
  tool_args_hash_algo TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_occurred_at ON audit_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_events (agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_server ON audit_events (server_id);
CREATE INDEX IF NOT EXISTS idx_audit_policy ON audit_events (policy_id);
