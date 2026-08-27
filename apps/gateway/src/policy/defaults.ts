/**
 * Default constants for the policy engine.
 *
 * DENY-by-default: an unconfigured gateway blocks all requests.
 * Operators must explicitly declare ALLOW policies before traffic flows.
 */

import type { PolicyDecision } from "./types.js";

/** Default decision when no policy matches — fail-closed. */
export const DEFAULT_DECISION: PolicyDecision = "DENY";

/** Human-readable reason for the default decision. */
export const DEFAULT_REASON = "No matching policy";

/**
 * Decision severity ranking. Higher number = more restrictive.
 * Used to resolve conflicts when multiple policies match.
 *
 * Priority CANNOT override severity: ALLOW can never beat DENY or REQUIRE_APPROVAL.
 */
export const SEVERITY: Record<PolicyDecision, number> = {
  DENY: 3,
  REQUIRE_APPROVAL: 2,
  ALLOW: 1,
};

/**
 * JSON-RPC error code for REQUIRE_APPROVAL responses.
 * Uses the server-defined error range (-32000 to -32099) per JSON-RPC spec.
 */
export const APPROVAL_ERROR_CODE = -32001;
