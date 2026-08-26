import { DEFAULT_UPSTREAM_URL } from "@aegis/protocol";

export const config = {
  port: Number(process.env.PORT ?? 3000),
  host: process.env.HOST ?? "0.0.0.0",
  upstreamUrl: process.env.UPSTREAM_URL ?? DEFAULT_UPSTREAM_URL,
  upstreamTimeoutMs: Number(process.env.UPSTREAM_TIMEOUT_MS ?? 30_000),
} as const;
