/**
 * Policy types for the AegisMCP policy engine.
 *
 * Policies are pure data — no executable expressions, no code, no side effects.
 * The policy engine evaluates a SecurityContext against an ordered list of
 * policies and returns a deterministic decision.
 */

/**
 * The decision a policy reaches when it matches a SecurityContext.
 *
 * - "ALLOW": request is forwarded to the upstream server unchanged.
 * - "DENY": request is blocked; upstream is never contacted.
 * - "REQUIRE_APPROVAL": request is blocked; upstream is never contacted.
 *   A structured error is returned indicating approval is required.
 */
export type PolicyDecision = "ALLOW" | "DENY" | "REQUIRE_APPROVAL";

/**
 * Conditions that determine when a policy applies.
 *
 * All specified fields must match the SecurityContext (AND logic).
 * Unspecified fields (undefined) match any value (wildcard).
 * An empty match object {} matches every SecurityContext.
 */
export interface PolicyMatch {
  /** Exact match on agent.id */
  readonly agent?: string;
  /** Exact match on server.id */
  readonly server?: string;
  /** Exact match on the MCP method (e.g. "tools/call", "tools/list") */
  readonly method?: string;
  /** Exact match on toolName (e.g. "echo", "database.delete") */
  readonly tool?: string;
}

/**
 * A single policy rule.
 *
 * Policies are evaluated in order. When multiple policies match,
 * the most restrictive decision wins (DENY > REQUIRE_APPROVAL > ALLOW),
 * broken by priority, then insertion order.
 */
export interface Policy {
  /** Unique identifier for this policy (human-readable, used in decisions and audit) */
  readonly id: string;
  /** The decision when this policy matches */
  readonly decision: PolicyDecision;
  /** Matching conditions — all specified fields must match */
  readonly match: PolicyMatch;
  /** Human-readable explanation of why this policy exists */
  readonly reason: string;
  /** Optional numeric priority. Higher values win within the same decision severity. Default: 0. */
  readonly priority?: number;
}

/**
 * The result of evaluating a SecurityContext against a policy set.
 *
 * This is the policy engine's output. Future audit systems can consume
 * (SecurityContext, PolicyEvaluation) pairs without coupling to the engine.
 */
export interface PolicyEvaluation {
  /** The decision reached */
  readonly decision: PolicyDecision;
  /** The ID of the matching policy, or null when the default decision fires (no match) */
  readonly policyId: string | null;
  /** Human-readable explanation — always non-empty */
  readonly reason: string;
}
