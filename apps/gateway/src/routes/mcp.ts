import type { FastifyInstance } from "fastify";

export async function mcpRoutes(fastify: FastifyInstance): Promise<void> {
  fastify.all("/mcp", async (_request, reply) => {
    return reply.status(501).send({
      error: "NotImplemented",
      message: "MCP proxy not yet implemented",
    });
  });
}
