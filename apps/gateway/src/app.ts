import Fastify from "fastify";
import { config } from "./config/index.js";
import { healthRoutes } from "./routes/health.js";
import { mcpRoutes } from "./routes/mcp.js";
import type { TrustedIdentityConfig } from "./security/identity.js";

export interface AppOptions {
  upstreamUrl?: string;
  upstreamTimeoutMs?: number;
  identity?: TrustedIdentityConfig;
}

export function buildApp(options?: AppOptions) {
  const app = Fastify({ logger: false });

  app.register(healthRoutes);
  app.register(mcpRoutes, {
    upstreamUrl: options?.upstreamUrl ?? config.upstreamUrl,
    upstreamTimeoutMs: options?.upstreamTimeoutMs ?? config.upstreamTimeoutMs,
    identity: options?.identity ?? config.identity,
  });

  return app;
}
