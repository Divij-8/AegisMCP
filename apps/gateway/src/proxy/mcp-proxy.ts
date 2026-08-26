import http from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "upgrade",
]);

const RESPONSE_TRANSPORT_HEADERS = new Set(["content-length", "transfer-encoding"]);

function filterRequestHeaders(
  headers: http.IncomingHttpHeaders,
): Record<string, string | string[]> {
  const filtered: Record<string, string | string[]> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (value !== undefined && !HOP_BY_HOP_HEADERS.has(key.toLowerCase())) {
      filtered[key] = value;
    }
  }
  return filtered;
}

function filterResponseHeaders(
  headers: http.IncomingHttpHeaders,
): Record<string, string | string[]> {
  const filtered: Record<string, string | string[]> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (
      value !== undefined &&
      !HOP_BY_HOP_HEADERS.has(key.toLowerCase()) &&
      !RESPONSE_TRANSPORT_HEADERS.has(key.toLowerCase())
    ) {
      filtered[key] = value;
    }
  }
  return filtered;
}

function sendError(reply: ServerResponse, status: number, error: string, message: string): void {
  if (reply.headersSent) {
    reply.end();
    return;
  }
  const body = JSON.stringify({ error, message });
  reply.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
  });
  reply.end(body);
}

export interface McpProxyOptions {
  upstreamUrl: string;
  upstreamTimeoutMs: number;
}

export function proxyMcpRequest(
  request: IncomingMessage,
  reply: ServerResponse,
  body: Buffer,
  options: McpProxyOptions,
): void {
  const upstream = new URL(options.upstreamUrl);

  const abortController = new AbortController();
  const timeout = setTimeout(() => abortController.abort(), options.upstreamTimeoutMs);

  const upstreamHeaders = filterRequestHeaders(request.headers);

  const upstreamReq = http.request(
    {
      hostname: upstream.hostname,
      port: upstream.port,
      path: upstream.pathname,
      method: request.method,
      headers: upstreamHeaders,
      signal: abortController.signal,
    },
    (upstreamRes: IncomingMessage) => {
      clearTimeout(timeout);

      const responseHeaders = filterResponseHeaders(upstreamRes.headers);

      reply.writeHead(upstreamRes.statusCode ?? 502, responseHeaders);
      upstreamRes.pipe(reply);
    },
  );

  upstreamReq.on("error", (err: NodeJS.ErrnoException) => {
    clearTimeout(timeout);

    if (err.code === "ECONNREFUSED" || err.code === "ENOTFOUND") {
      sendError(reply, 502, "BadGateway", "Upstream MCP server unavailable");
    } else if (err.name === "AbortError") {
      sendError(reply, 504, "GatewayTimeout", "Upstream MCP server timed out");
    } else {
      sendError(reply, 502, "BadGateway", `Upstream error: ${err.message}`);
    }
  });

  request.on("close", () => {
    if (request.complete || reply.writableFinished) {
      return;
    }
    if (!upstreamReq.destroyed) {
      abortController.abort();
    }
  });

  upstreamReq.write(body);
  upstreamReq.end();
}
