export interface AgentIdentity {
  readonly id: string;
  readonly name: string;
}

export interface ServerIdentity {
  readonly id: string;
  readonly name: string;
  readonly upstreamUrl: string;
}

export interface TrustedIdentityConfig {
  readonly agent: AgentIdentity;
  readonly server: ServerIdentity;
}

export interface IdentityOverrides {
  readonly agentId?: string;
  readonly agentName?: string;
  readonly serverId?: string;
  readonly serverName?: string;
  readonly upstreamUrl?: string;
}

const DEFAULT_AGENT_ID = "default-agent";
const DEFAULT_AGENT_NAME = "default-agent";
const DEFAULT_SERVER_ID = "aegis-mock-mcp-server";
const DEFAULT_SERVER_NAME = "aegis-mock-mcp-server";

export function resolveIdentity(overrides?: IdentityOverrides): TrustedIdentityConfig {
  const agent: AgentIdentity = Object.freeze({
    id: overrides?.agentId ?? process.env.AGENT_ID ?? DEFAULT_AGENT_ID,
    name: overrides?.agentName ?? process.env.AGENT_NAME ?? DEFAULT_AGENT_NAME,
  });

  const server: ServerIdentity = Object.freeze({
    id: overrides?.serverId ?? process.env.SERVER_ID ?? DEFAULT_SERVER_ID,
    name: overrides?.serverName ?? process.env.SERVER_NAME ?? DEFAULT_SERVER_NAME,
    upstreamUrl: overrides?.upstreamUrl ?? process.env.UPSTREAM_URL ?? "http://127.0.0.1:3001/mcp",
  });

  return Object.freeze({ agent, server });
}
