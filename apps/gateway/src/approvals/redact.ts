/**
 * Tool-argument sanitization — pure functions, no IO.
 *
 * Two separate concerns:
 *  1. redactArguments(): produce a display/persist-safe copy where secret-looking
 *     values are replaced. Used for approval records and audit metadata.
 *  2. hashArguments(): a deterministic digest of the EXACT original arguments,
 *     used to bind an approval to the request it was created for.
 *
 * Neither function ever mutates its input.
 */

import { createHash } from "node:crypto";

export const ARGS_HASH_ALGORITHM = "sha256";
export const REDACTED = "[REDACTED]";

/** Keys whose values are treated as secret regardless of content. */
const SENSITIVE_KEY_PATTERN =
  /(pass(word|phrase)?|secret|token|api[-_]?key|access[-_]?key|private[-_]?key|credential|authorization|auth|cookie|session|bearer|client[-_]?secret|signature)/i;

/** Values longer than this are truncated before storage/display. */
const MAX_STRING_LENGTH = 1024;
/** Maximum nesting depth copied before deeper structures are replaced. */
const MAX_DEPTH = 8;
/** Maximum number of entries copied per object/array. */
const MAX_ENTRIES = 200;

export function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY_PATTERN.test(key);
}

function truncate(value: string): string {
  if (value.length <= MAX_STRING_LENGTH) return value;
  return `${value.slice(0, MAX_STRING_LENGTH)}…[truncated]`;
}

function redactValue(value: unknown, depth: number): unknown {
  if (depth > MAX_DEPTH) return "[TRUNCATED]";

  if (value === null || typeof value === "number" || typeof value === "boolean") {
    return value;
  }

  if (typeof value === "string") {
    return truncate(value);
  }

  if (Array.isArray(value)) {
    return value.slice(0, MAX_ENTRIES).map((entry) => redactValue(entry, depth + 1));
  }

  if (typeof value === "object") {
    const result: Record<string, unknown> = {};
    let count = 0;
    for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
      if (count >= MAX_ENTRIES) {
        result["…"] = "[TRUNCATED]";
        break;
      }
      result[key] = isSensitiveKey(key) ? REDACTED : redactValue(entry, depth + 1);
      count++;
    }
    return result;
  }

  // functions, symbols, undefined, bigint → not representable in JSON tool args
  return "[UNSUPPORTED]";
}

/**
 * Produce a safe copy of tool arguments. Sensitive values are replaced with
 * "[REDACTED]", deep structures are depth/size bounded, and long strings are
 * truncated. Undefined means "no arguments" and stays undefined.
 */
export function redactArguments(
  args: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (args === undefined) return undefined;
  return redactValue(args, 0) as Record<string, unknown>;
}

/** Deterministic JSON with sorted keys so the digest is stable across runs. */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalize(entry)).join(",")}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, entry]) => entry !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries
    .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalize(entry)}`)
    .join(",")}}`;
}

/**
 * Digest of the EXACT arguments used for approval binding. Computed from the
 * original values (never the redacted copy) so a request cannot be replayed
 * with subtly different arguments.
 */
export function hashArguments(args: Record<string, unknown> | undefined): string {
  const canonical = canonicalize(args ?? null);
  return createHash(ARGS_HASH_ALGORITHM).update(canonical).digest("hex");
}
