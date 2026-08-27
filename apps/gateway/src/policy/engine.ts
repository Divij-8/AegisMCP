/**
 * Policy engine — evaluates a SecurityContext against an ordered list
 * of policies and returns a deterministic PolicyEvaluation.
 *
 * Precedence:
 * 1. Collect all matching policies.
 * 2. Higher decision severity wins: DENY(3) > REQUIRE_APPROVAL(2) > ALLOW(1).
 * 3. Higher numeric priority wins within same severity.
 * 4. Earlier insertion order wins when severity and priority are tied.
 *
 * Priority CANNOT override severity: ALLOW can never beat DENY or REQUIRE_APPROVAL.
 *
 * Default behavior: DENY when no policy matches (fail-closed).
 */

import type { SecurityContext } from "../mcp/types.js";
import type { Policy, PolicyEvaluation } from "./types.js";
import { matchesPolicy } from "./matcher.js";
import { DEFAULT_DECISION, DEFAULT_REASON, SEVERITY } from "./defaults.js";
import { validatePolicies } from "./validate.js";

export class PolicyEngine {
  private readonly policies: readonly Policy[];

  constructor(policies: Policy[]) {
    validatePolicies(policies);
    this.policies = Object.freeze([...policies]);
  }

  /**
   * Evaluate a SecurityContext against the configured policies.
   *
   * @param context - The parsed security context of the incoming request
   * @returns A deterministic PolicyEvaluation
   */
  evaluate(context: SecurityContext): PolicyEvaluation {
    const matching: Policy[] = [];

    for (const policy of this.policies) {
      if (matchesPolicy(context, policy.match)) {
        matching.push(policy);
      }
    }

    if (matching.length === 0) {
      return {
        decision: DEFAULT_DECISION,
        policyId: null,
        reason: DEFAULT_REASON,
      };
    }

    if (matching.length === 1) {
      const policy = matching[0]!;
      return {
        decision: policy.decision,
        policyId: policy.id,
        reason: policy.reason,
      };
    }

    const first = matching[0]!;
    const winner = matching.slice(1).reduce<Policy>((best, current) => {
      const bestSeverity = SEVERITY[best.decision];
      const currentSeverity = SEVERITY[current.decision];
      if (currentSeverity !== bestSeverity) {
        return currentSeverity > bestSeverity ? current : best;
      }

      const bestPriority = best.priority ?? 0;
      const currentPriority = current.priority ?? 0;
      if (currentPriority !== bestPriority) {
        return currentPriority > bestPriority ? current : best;
      }

      return best;
    }, first);
    return {
      decision: winner.decision,
      policyId: winner.id,
      reason: winner.reason,
    };
  }
}
