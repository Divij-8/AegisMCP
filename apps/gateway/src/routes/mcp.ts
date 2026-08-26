import type { FastifyInstance } from "fastify";
import { proxyMcpRequest } from "../proxy/mcp-proxy.js";

export interface McpRoutesOptions {
  upstreamUrl: string;
  upstreamTimeoutMs: number;
}

export async function mcpRoutes(
  fastify: FastifyInstance,
  options: McpRoutesOptions,
): Promise<void> {
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
