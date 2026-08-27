import { DEFAULT_UPSTREAM_URL } from "@aegis/protocol";
import { resolveIdentity } from "../security/identity.js";
import type { Policy } from "../policy/types.js";

export const config = {
  port: Number(process.env.PORT ?? 3000),
  host: process.env.HOST ?? "0.0.0.0",
  upstreamUrl: process.env.UPSTREAM_URL ?? DEFAULT_UPSTREAM_URL,
  upstreamTimeoutMs: Number(process.env.UPSTREAM_TIMEOUT_MS ?? 30_000),
  identity: resolveIdentity(),
  policies: [] as Policy[],
} as const;
