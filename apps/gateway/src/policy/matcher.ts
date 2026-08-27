/**
 * Policy matcher — pure predicate that checks if a SecurityContext
 * matches a PolicyMatch condition.
 *
 * All specified fields must match (AND logic).
 * Unspecified fields (undefined) match any value (wildcard).
 * An empty match {} matches every SecurityContext.
 */

import type { SecurityContext } from "../mcp/types.js";
import type { PolicyMatch } from "./types.js";

/**
 * Check if a SecurityContext matches a PolicyMatch condition.
 *
 * @param context - The parsed security context of the incoming request
 * @param match - The policy match conditions
 * @returns true if all specified fields match
 */
export function matchesPolicy(context: SecurityContext, match: PolicyMatch): boolean {
  if (match.agent !== undefined && context.agent.id !== match.agent) {
    return false;
  }

  if (match.server !== undefined && context.server.id !== match.server) {
    return false;
  }

  if (match.method !== undefined && context.method !== match.method) {
    return false;
  }

  if (match.tool !== undefined && context.toolName !== match.tool) {
    return false;
  }

  return true;
}
