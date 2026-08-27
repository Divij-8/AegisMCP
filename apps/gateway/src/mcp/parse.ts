/**
 * MCP request normalization layer.
 *
 * Parses raw request Buffers into SecurityContexts or normalization errors.
 * Operates exclusively on a JSON.parse copy — the original Buffer is never
 * mutated or reconstructed. The caller retains the original bytes for
 * transparent proxy forwarding.
 */

import {
  PARSE_ERROR,
  INVALID_REQUEST,
  INVALID_PARAMS,
  PROTOCOL_VERSION_META_KEY,
} from "@modelcontextprotocol/server";
import type { TrustedIdentityConfig } from "../security/identity.js";
import type {
  NormalizationError,
  ParseResult,
  RequestId,
  SecurityContext,
} from "./types.js";

function extractProtocolVersion(params: Record<string, unknown> | undefined): string | undefined {
  if (params == null) return undefined;

  const meta = params["_meta"];
  if (typeof meta === "object" && meta !== null) {
    const version = (meta as Record<string, unknown>)[PROTOCOL_VERSION_META_KEY];
    if (typeof version === "string") return version;
  }

  const pv = params["protocolVersion"];
  if (typeof pv === "string") return pv;

  return undefined;
}

function extractToolFields(
  method: string,
  params: Record<string, unknown> | undefined,
): { toolName: string | undefined; toolArguments: Record<string, unknown> | undefined } {
  if (method !== "tools/call" || params == null) {
    return { toolName: undefined, toolArguments: undefined };
  }

  const name = params["name"];
  const args = params["arguments"];

  return {
    toolName: typeof name === "string" ? name : undefined,
    toolArguments:
      typeof args === "object" && args !== null && !Array.isArray(args)
        ? (args as Record<string, unknown>)
        : undefined,
  };
}

/**
 * Parse a raw MCP request body Buffer into a ParseResult.
 *
 * The original Buffer is never mutated. All inspection operates on
 * a JSON.parse copy.
 *
 * @param body - The raw request body as a Buffer
 * @param identity - Trusted identity configuration (from server config, not client)
 * @returns ParseResult discriminated union
 */
export function parseMcpRequest(
  body: Buffer,
  identity: TrustedIdentityConfig,
): ParseResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString("utf-8"));
  } catch {
    return {
      kind: "error",
      error: { code: PARSE_ERROR, message: "Parse error" },
    };
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return {
      kind: "error",
      error: { code: INVALID_REQUEST, message: "Invalid Request" },
    };
  }

  const envelope = parsed as Record<string, unknown>;

  if (envelope["jsonrpc"] !== "2.0") {
    return {
      kind: "error",
      error: { code: INVALID_REQUEST, message: "Invalid Request" },
    };
  }

  const hasId = "id" in envelope && (typeof envelope["id"] === "string" || typeof envelope["id"] === "number");
  const hasMethod = typeof envelope["method"] === "string";

  if (!hasMethod) {
    return {
      kind: "error",
      error: { code: INVALID_REQUEST, message: "Invalid Request" },
    };
  }

  if (!hasId) {
    return { kind: "notification" };
  }

  const requestId = envelope["id"] as RequestId;
  const method = envelope["method"] as string;
  const params =
    typeof envelope["params"] === "object" && envelope["params"] !== null
      ? (envelope["params"] as Record<string, unknown>)
      : undefined;

  const protocolVersion = extractProtocolVersion(params);

  if (method === "tools/call") {
    if (params == null || typeof params["name"] !== "string") {
      return {
        kind: "error",
        error: { code: INVALID_PARAMS, message: "Invalid params" },
      };
    }
    if ("arguments" in params && params["arguments"] != null) {
      if (
        typeof params["arguments"] !== "object" ||
        Array.isArray(params["arguments"])
      ) {
        return {
          kind: "error",
          error: { code: INVALID_PARAMS, message: "Invalid params" },
        };
      }
    }
  }

  const { toolName, toolArguments } = extractToolFields(method, params);

  const context: SecurityContext = {
    requestId,
    protocolVersion,
    method,
    toolName,
    toolArguments,
    agent: identity.agent,
    server: identity.server,
    timestamp: Date.now(),
  };

  return { kind: "request", context };
}

/**
 * Serialize a NormalizationError into a JSON-RPC error response body.
 *
 * The id is null when we cannot extract it from the original request
 * (malformed envelope). Otherwise the original id is echoed back per
 * JSON-RPC specification.
 */
export function serializeJsonRpcError(
  error: NormalizationError,
  requestId: RequestId | null,
): string {
  return JSON.stringify({
    jsonrpc: "2.0",
    id: requestId,
    error: {
      code: error.code,
      message: error.message,
      ...(error.data !== undefined ? { data: error.data } : {}),
    },
  });
}
