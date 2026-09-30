/**
 * API credential format — pure, transport-independent, no IO.
 *
 * Wire format:  amcp_<keyId>_<secret>
 *   - prefix  : literal "amcp" (identifies an AegisMCP credential)
 *   - keyId   : 16 random bytes, hex encoded — a PUBLIC lookup identifier,
 *               safe to store and to record in the audit trail
 *   - secret  : 32 random bytes, hex encoded — SECRET material, never stored
 *               and never logged
 *
 * Hex encoding is deliberate: it contains no "_" so the three segments are
 * unambiguous without length guessing, and it validates with a single regex.
 *
 * Nothing in this module reads HTTP headers directly. The transport layer
 * passes plain header values into extractPresentedCredential, keeping the
 * security layer free of Fastify/HTTP coupling.
 */

import { randomBytes } from "node:crypto";

export const API_KEY_PREFIX = "amcp";

const KEY_ID_BYTES = 16;
const SECRET_BYTES = 32;

const HEX_PATTERN = /^[0-9a-f]+$/;
const KEY_ID_HEX_LENGTH = KEY_ID_BYTES * 2;
const SECRET_HEX_LENGTH = SECRET_BYTES * 2;

/** Structured view of a well-formed API key. Never log the secret field. */
export interface ParsedApiKey {
  readonly keyId: string;
  readonly secret: string;
}

export function generateKeyId(): string {
  return randomBytes(KEY_ID_BYTES).toString("hex");
}

export function generateSecret(): string {
  return randomBytes(SECRET_BYTES).toString("hex");
}

export function formatApiKey(keyId: string, secret: string): string {
  return `${API_KEY_PREFIX}_${keyId}_${secret}`;
}

/**
 * Parse a presented API key. Returns null for anything malformed — the caller
 * must not echo the presented value back in errors or logs.
 */
export function parseApiKey(presented: string): ParsedApiKey | null {
  const parts = presented.split("_");
  if (parts.length !== 3) return null;

  const [prefix, keyId, secret] = parts as [string, string, string];
  if (prefix !== API_KEY_PREFIX) return null;
  if (keyId.length !== KEY_ID_HEX_LENGTH || !HEX_PATTERN.test(keyId)) return null;
  if (secret.length !== SECRET_HEX_LENGTH || !HEX_PATTERN.test(secret)) return null;

  return { keyId, secret };
}

/** Header values as the transport layer sees them (plain strings, no Fastify). */
export interface PresentedHeaders {
  readonly authorization?: string | string[] | undefined;
  readonly apiKey?: string | string[] | undefined;
}

/**
 * Outcome of reading a credential out of request headers.
 *
 * - "none"      → no credential was presented
 * - "presented" → a value was presented (validity is for the authenticator to decide)
 */
export type CredentialExtraction =
  { readonly kind: "none" } | { readonly kind: "presented"; readonly value: string };

function firstHeaderValue(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}

/**
 * Read the presented credential from headers.
 *
 * Precedence: `Authorization: Bearer <key>` first, then `X-API-Key: <key>`.
 * A non-empty Authorization header that is not a Bearer token is returned as
 * presented (and will fail as malformed) rather than being ignored.
 */
export function extractPresentedCredential(headers: PresentedHeaders): CredentialExtraction {
  const authorization = firstHeaderValue(headers.authorization)?.trim();
  if (authorization !== undefined && authorization.length > 0) {
    const bearer = /^Bearer\s+(.+)$/i.exec(authorization);
    if (bearer === null) return { kind: "presented", value: authorization };
    return { kind: "presented", value: bearer[1]!.trim() };
  }

  const apiKey = firstHeaderValue(headers.apiKey)?.trim();
  if (apiKey !== undefined && apiKey.length > 0) {
    return { kind: "presented", value: apiKey };
  }

  return { kind: "none" };
}
