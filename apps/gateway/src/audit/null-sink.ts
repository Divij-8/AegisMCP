/**
 * No-op audit sink — used when persistence is disabled (no DATABASE_URL).
 * Preserves pre-Phase-4 behavior exactly: zero overhead, zero output.
 */

import type { AuditEvent, AuditSink, AuditSinkStats } from "./types.js";

const EMPTY_STATS: AuditSinkStats = { queued: 0, flushed: 0, failed: 0, dropped: 0 };

export class NullAuditSink implements AuditSink {
  record(_event: AuditEvent): void {
    /* persistence disabled */
  }

  async flush(): Promise<void> {
    /* nothing queued, ever */
  }

  async close(): Promise<void> {
    /* nothing to release */
  }

  stats(): AuditSinkStats {
    return EMPTY_STATS;
  }
}
