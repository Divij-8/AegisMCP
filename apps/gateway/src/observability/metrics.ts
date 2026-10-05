/**
 * In-process metrics registry.
 *
 * Deliberately dependency-free: monotonically increasing counters plus a few
 * gauges read at scrape time. This is enough for structured logging/metrics
 * without adding a metrics framework or infrastructure. Names follow the
 * Prometheus convention (snake_case, _total suffix) so they can be exported
 * later without renaming.
 */

export const METRIC = {
  mcpRequests: "aegis_mcp_requests_total",
  mcpAuthFailures: "aegis_mcp_auth_failures_total",
  mcpPolicyAllow: "aegis_policy_allow_total",
  mcpPolicyDeny: "aegis_policy_deny_total",
  mcpPolicyRequireApproval: "aegis_policy_require_approval_total",
  mcpUpstreamErrors: "aegis_upstream_errors_total",
  mcpUpstreamTimeouts: "aegis_upstream_timeouts_total",
  approvalsApproved: "aegis_approvals_approved_total",
  approvalsDenied: "aegis_approvals_denied_total",
  approvalsConsumed: "aegis_approvals_consumed_total",
  policyReloads: "aegis_policy_reloads_total",
  adminRequests: "aegis_admin_requests_total",
  adminAuthFailures: "aegis_admin_auth_failures_total",
} as const;

export type MetricName = (typeof METRIC)[keyof typeof METRIC];

export class Metrics {
  private readonly counters = new Map<string, number>();

  increment(name: string, by = 1): void {
    if (by <= 0) return;
    this.counters.set(name, (this.counters.get(name) ?? 0) + by);
  }

  /** Point-in-time counter snapshot. Stable key order for readable output. */
  snapshot(): Readonly<Record<string, number>> {
    return Object.freeze(
      Object.fromEntries([...this.counters.entries()].sort(([a], [b]) => (a < b ? -1 : 1))),
    );
  }
}
