/**
 * Policy validation — runs at startup to catch configuration errors
 * before any requests are processed.
 *
 * Throws on invalid policy definitions. Fail-closed: bad config = no startup.
 */

import type { Policy } from "./types.js";

/**
 * Validate an array of policies at startup time.
 *
 * Checks:
 * - Every policy has a non-empty id
 * - Policy ids are unique
 * - Decision is a valid PolicyDecision value
 * - Match object exists (empty {} is valid — catch-all)
 *
 * @throws {Error} with descriptive message on first invalid policy
 */
export function validatePolicies(policies: Policy[]): void {
  const seenIds = new Set<string>();

  for (let i = 0; i < policies.length; i++) {
    const policy = policies[i]!;
    const label = `Policy at index ${i}`;

    if (typeof policy.id !== "string" || policy.id.trim() === "") {
      throw new Error(`${label}: id must be a non-empty string`);
    }

    if (seenIds.has(policy.id)) {
      throw new Error(`${label}: duplicate id "${policy.id}"`);
    }
    seenIds.add(policy.id);

    if (!["ALLOW", "DENY", "REQUIRE_APPROVAL"].includes(policy.decision)) {
      throw new Error(`${label} ("${policy.id}"): invalid decision "${String(policy.decision)}"`);
    }

    if (typeof policy.match !== "object" || policy.match === null || Array.isArray(policy.match)) {
      throw new Error(`${label} ("${policy.id}"): match must be an object`);
    }

    if (typeof policy.reason !== "string" || policy.reason.trim() === "") {
      throw new Error(`${label} ("${policy.id}"): reason must be a non-empty string`);
    }

    if (policy.enabled !== undefined && typeof policy.enabled !== "boolean") {
      throw new Error(`${label} ("${policy.id}"): enabled must be a boolean`);
    }

    validateArgumentConstraints(policy, label);
  }
}

function validateArgumentConstraints(policy: Policy, label: string): void {
  const constraints = (policy.match as { arguments?: unknown }).arguments;
  if (constraints === undefined) return;

  if (typeof constraints !== "object" || constraints === null || Array.isArray(constraints)) {
    throw new Error(`${label} ("${policy.id}"): match.arguments must be an object`);
  }

  for (const [key, raw] of Object.entries(constraints as Record<string, unknown>)) {
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
      throw new Error(`${label} ("${policy.id}"): match.arguments.${key} must be an object`);
    }
    const constraint = raw as Record<string, unknown>;
    const hasEquals = "equals" in constraint;
    const hasOneOf = "oneOf" in constraint;
    if (hasEquals === hasOneOf) {
      throw new Error(
        `${label} ("${policy.id}"): match.arguments.${key} must set exactly one of equals/oneOf`,
      );
    }
    if (hasOneOf && !Array.isArray(constraint["oneOf"])) {
      throw new Error(`${label} ("${policy.id}"): match.arguments.${key}.oneOf must be an array`);
    }
  }
}
