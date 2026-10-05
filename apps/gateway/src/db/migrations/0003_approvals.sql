-- 0003_approvals.sql — AegisMCP human-in-the-loop approval workflow (forward-only).
--
-- Design notes:
-- - An approval records a REQUIRE_APPROVAL decision. It NEVER carries execution
--   authority by itself: the gateway re-evaluates policy for the request that
--   presents it and consumes the approval at most once (consumed_at).
-- - `arguments` stores ONLY REDACTED tool arguments. Secret-looking values are
--   replaced before persistence; raw arguments never reach this table.
-- - args_hash binds an approval to the exact request it was created for
--   (agent + server + method + tool + arguments). A different request cannot be
--   authorized with the same approval id.
-- - expires_at is mandatory: expired approvals can never be approved or executed.
-- - The partial unique index makes approval creation idempotent per binding
--   while PENDING so retries do not spawn duplicate approval requests.

ALTER TABLE agents ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'AGENT'
  CHECK (role IN ('ADMIN', 'OPERATOR', 'AUDITOR', 'AGENT'));

CREATE TABLE IF NOT EXISTS approvals (
  id              TEXT PRIMARY KEY,                     -- public approval id
  request_id      TEXT,                                 -- originating JSON-RPC id
  agent_id        TEXT NOT NULL REFERENCES agents(id),
  server_id       TEXT NOT NULL REFERENCES mcp_servers(id),
  method          TEXT NOT NULL,
  tool_name       TEXT,
  arguments       JSONB NOT NULL DEFAULT '{}'::jsonb,   -- REDACTED arguments only
  args_hash       TEXT NOT NULL,                        -- sha256 of the exact original args
  args_hash_algo  TEXT NOT NULL,                        -- e.g. 'sha256'
  policy_id       TEXT,
  decision        TEXT NOT NULL CHECK (decision = 'REQUIRE_APPROVAL'),
  reason          TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at      TIMESTAMPTZ NOT NULL,
  status          TEXT NOT NULL CHECK (status IN ('PENDING', 'APPROVED', 'DENIED', 'EXPIRED')),
  approver_id     TEXT,                                 -- agent id of the deciding administrator
  decided_at      TIMESTAMPTZ,
  decision_reason TEXT,
  consumed_at     TIMESTAMPTZ,                          -- set exactly once, when executed
  consumed_by     TEXT                                  -- agent id that consumed it (must be owner)
);

-- At most one PENDING approval per exact binding; retries reuse it.
CREATE UNIQUE INDEX IF NOT EXISTS idx_approvals_pending_binding
  ON approvals (agent_id, server_id, method, COALESCE(tool_name, ''), args_hash)
  WHERE status = 'PENDING';

CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals (status, expires_at);
CREATE INDEX IF NOT EXISTS idx_approvals_agent ON approvals (agent_id);
CREATE INDEX IF NOT EXISTS idx_approvals_server ON approvals (server_id);

-- Extend audit_events for the approval lifecycle. Constraint names match the
-- auto-generated ones from 0001 and are recreated as supersets so rows written
-- by older code during a rolling deploy remain valid.
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_event_type_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_event_type_check
  CHECK (
    event_type IN (
      'request', 'notification', 'auth', 'admin',
      'approval_created', 'approval_approved', 'approval_denied', 'approval_expired'
    )
  );

ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_outcome_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_outcome_check
  CHECK (outcome IN ('blocked', 'forwarded', 'upstream_error', 'auth_failed', 'pending'));

ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS approval_id TEXT;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS risk_level TEXT
  CHECK (risk_level IS NULL OR risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'));

CREATE INDEX IF NOT EXISTS idx_audit_approval ON audit_events (approval_id);
CREATE INDEX IF NOT EXISTS idx_audit_risk ON audit_events (risk_level);
