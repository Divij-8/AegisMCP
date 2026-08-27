import type { AgentIdentity, ServerIdentity } from "../security/identity.js";

export type RequestId = string | number;

/**
 * Normalized security-relevant representation of an actionable MCP request.
 *
 * This is transport-independent — it contains no HTTP headers, sockets,
 * Fastify objects, or Node.js IncomingMessage references.
 *
 * It is observational only (Phase 2) — no policy decisions are made from it yet.
 */
export interface SecurityContext {
  /** JSON-RPC request id — preserved for error correlation */
  readonly requestId: RequestId;

  /** MCP protocol version from _meta envelope or params, if present */
  readonly protocolVersion: string | undefined;

  /** Raw MCP method string, e.g. "tools/call", "tools/list", "server/discover" */
  readonly method: string;

  /** Tool name — only present for "tools/call" */
  readonly toolName: string | undefined;

  /** Tool arguments — only present for "tools/call" */
  readonly toolArguments: Record<string, unknown> | undefined;

  /** Trusted agent identity (from server config, NOT from client) */
  readonly agent: AgentIdentity;

  /** Upstream server identity (from server config) */
  readonly server: ServerIdentity;

  /** Gateway-local timestamp (Date.now()) when the request was received */
  readonly timestamp: number;
}

/**
 * JSON-RPC error produced by normalization failure.
 * Uses standard JSON-RPC error codes — no invented codes.
 */
export interface NormalizationError {
  /** JSON-RPC error code (e.g. -32700, -32600, -32602) */
  readonly code: number;
  /** Human-readable error description */
  readonly message: string;
  /** Optional structured data about the error */
  readonly data?: unknown;
}

/**
 * Result of parsing an MCP request body.
 *
 * - "request": valid actionable request → SecurityContext
 * - "notification": valid notification (no id) → forward without context
 * - "error": malformed input → NormalizationError
 */
export type ParseResult =
  | { readonly kind: "request"; readonly context: SecurityContext }
  | { readonly kind: "notification" }
  | { readonly kind: "error"; readonly error: NormalizationError };
