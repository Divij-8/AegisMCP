-- 0002_agent_credentials.sql — AegisMCP agent authentication schema (forward-only).
--
-- Design notes:
-- - Only SECRET HASHES are stored. The plaintext API key never reaches the
--   database: secret_hash is an scrypt-derived value and salt is per-credential.
-- - key_id is a PUBLIC lookup identifier (like an access-key id). It is safe to
--   store and to record in the audit trail; it is not secret material.
-- - Revocation is soft (revoked_at) so history is preserved and rotation is
--   symmetric: create a new credential, deploy it, revoke the old one.
-- - Multiple live credentials per agent are allowed by design.
-- - last_used_at is reserved for future observability and is NEVER written by
--   the gateway today (a write on every request would sit on the proxy hot path).

CREATE TABLE IF NOT EXISTS agent_credentials (
  key_id       TEXT PRIMARY KEY,                        -- public lookup id (never secret)
  agent_id     TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  label        TEXT,
  secret_hash  TEXT NOT NULL,                           -- scrypt output (hex)
  salt         TEXT NOT NULL,                           -- per-credential salt (hex)
  hash_algo    TEXT NOT NULL,                           -- e.g. 'scrypt-v1'
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ,                             -- optional rotation bound
  revoked_at   TIMESTAMPTZ,                             -- NULL = active
  last_used_at TIMESTAMPTZ                              -- reserved; not written today
);

-- key_id lookups use the primary key index; agent lookups need their own.
CREATE INDEX IF NOT EXISTS idx_agent_credentials_agent ON agent_credentials (agent_id);

-- Extend audit_events for the authentication gate.
--
-- 0001 created the event_type / outcome CHECK constraints with PostgreSQL's
-- default auto-generated names. They are dropped by name and re-created as
-- supersets, so this migration is compatible with rows written by older code
-- during a rolling deploy.
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_event_type_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_event_type_check
  CHECK (event_type IN ('request', 'notification', 'auth'));

ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_outcome_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_outcome_check
  CHECK (outcome IN ('blocked', 'forwarded', 'upstream_error', 'auth_failed'));

-- Authentication failures may occur before any agent is known (missing,
-- malformed, or unknown credentials), so agent_id must be nullable for those
-- rows. Every other event type still always carries an agent.
ALTER TABLE audit_events ALTER COLUMN agent_id DROP NOT NULL;

-- Public key identifier of the presented credential (never the secret itself).
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS key_id TEXT;

-- Auth-failure lookups are commonly by key id; without this the audit table
-- would be sequentially scanned for those queries.
CREATE INDEX IF NOT EXISTS idx_audit_key_id ON audit_events (key_id);

-- Precise internal failure taxonomy. Client-facing responses stay generic so
-- this value never becomes a credential-enumeration oracle.
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS auth_failure_reason TEXT
  CHECK (
    auth_failure_reason IS NULL
    OR auth_failure_reason IN ('missing', 'malformed', 'unknown', 'revoked', 'expired', 'invalid', 'error')
  );
