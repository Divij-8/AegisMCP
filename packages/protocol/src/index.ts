export const PROTOCOL_VERSION = "2026-07-28" as const;

/**
 * MCP protocol versions this gateway stack supports.
 * Requests that explicitly declare an unsupported version are rejected
 * at normalization time with a JSON-RPC INVALID_REQUEST error.
 * A request with no version declaration is accepted (absence ≠ legacy).
 */
export const SUPPORTED_PROTOCOL_VERSIONS = ["2026-07-28"] as const;

export const MOCK_SERVER_NAME = "aegis-mock-mcp-server" as const;
export const MOCK_SERVER_VERSION = "0.0.1" as const;
export const MOCK_SERVER_PORT = 3001 as const;

export const GATEWAY_PORT = 3000 as const;
export const DEFAULT_UPSTREAM_URL = "http://127.0.0.1:3001/mcp" as const;
