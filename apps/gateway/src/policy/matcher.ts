/**
 * Policy matcher — pure predicate that checks if a SecurityContext
 * matches a PolicyMatch condition.
 *
 * All specified fields must match (AND logic).
 * Unspecified fields (undefined) match any value (wildcard).
 * An empty match {} matches every SecurityContext.
 */

import type { SecurityContext } from "../mcp/types.js";
import type { ArgumentConstraint, PolicyMatch } from "./types.js";

/**
 * Structural JSON equality for argument constraints. Order-independent for
 * object keys; arrays are order-sensitive (as JSON values generally are).
 */
function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null) return false;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((entry, index) => deepEqual(entry, b[index]));
  }
  if (typeof a === "object" && typeof b === "object") {
    const aKeys = Object.keys(a as Record<string, unknown>).sort();
    const bKeys = Object.keys(b as Record<string, unknown>).sort();
    if (aKeys.length !== bKeys.length) return false;
    return aKeys.every(
      (key, index) =>
        key === bKeys[index] &&
        deepEqual((a as Record<string, unknown>)[key], (b as Record<string, unknown>)[key]),
    );
  }
  return false;
}

function matchesConstraint(value: unknown, constraint: ArgumentConstraint): boolean {
  if (constraint.equals !== undefined) return deepEqual(value, constraint.equals);
  if (constraint.oneOf !== undefined)
    return constraint.oneOf.some((allowed) => deepEqual(value, allowed));
  // A constraint with neither operator can never match (fail closed).
  return false;
}

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

  if (match.arguments !== undefined) {
    const args = context.toolArguments;
    if (args === undefined) return false;
    for (const [key, constraint] of Object.entries(match.arguments)) {
      if (!matchesConstraint(args[key], constraint)) return false;
    }
  }

  return true;
}
