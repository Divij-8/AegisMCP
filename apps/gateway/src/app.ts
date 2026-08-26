import Fastify from "fastify";
import { healthRoutes } from "./routes/health.js";
import { mcpRoutes } from "./routes/mcp.js";

export function buildApp() {
  const app = Fastify({ logger: true });

  app.register(healthRoutes);
  app.register(mcpRoutes);

  return app;
}
