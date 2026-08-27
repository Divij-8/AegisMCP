import type { FastifyInstance } from "fastify";
import { proxyMcpRequest } from "../proxy/mcp-proxy.js";
import { parseMcpRequest, serializeJsonRpcError } from "../mcp/parse.js";
import type { TrustedIdentityConfig } from "../security/identity.js";

export interface McpRoutesOptions {
  upstreamUrl: string;
  upstreamTimeoutMs: number;
  identity: TrustedIdentityConfig;
}

export async function mcpRoutes(
  fastify: FastifyInstance,
  options: McpRoutesOptions,
): Promise<void> {
  fastify.removeContentTypeParser("application/json");
  fastify.addContentTypeParser("*", { parseAs: "buffer" }, (_req, body, done) => {
    done(null, body);
  });

  fastify.all("/mcp", async (request, reply) => {
    const raw = request.body;
    const body = Buffer.isBuffer(raw)
      ? raw
      : typeof raw === "string"
        ? Buffer.from(raw)
        : raw != null
          ? Buffer.from(JSON.stringify(raw))
          : Buffer.alloc(0);

    const parseResult = parseMcpRequest(body, options.identity);

    if (parseResult.kind === "error") {
      reply.code(200);
      reply.send(serializeJsonRpcError(parseResult.error, null));
      return reply;
    }

    reply.hijack();

    return new Promise<void>((resolve) => {
      reply.raw.on("finish", () => resolve());
      proxyMcpRequest(request.raw, reply.raw, body, {
        upstreamUrl: options.upstreamUrl,
        upstreamTimeoutMs: options.upstreamTimeoutMs,
      });
    });
  });
}
