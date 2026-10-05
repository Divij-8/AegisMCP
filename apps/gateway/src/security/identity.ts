import { isAgentRole, type AgentRole } from "./rbac.js";

export interface AgentIdentity {
  readonly id: string;
  readonly name: string;
  /**
   * Authorization role for the control plane. Optional for backward
   * compatibility; absent means AGENT (no control-plane permissions).
   */
  readonly role?: AgentRole;
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
  readonly agentRole?: AgentRole;
  readonly serverId?: string;
  readonly serverName?: string;
  readonly upstreamUrl?: string;
}

const DEFAULT_AGENT_ID = "default-agent";
const DEFAULT_AGENT_NAME = "default-agent";
const DEFAULT_SERVER_ID = "aegis-mock-mcp-server";
const DEFAULT_SERVER_NAME = "aegis-mock-mcp-server";

function resolveRoleOverride(raw: string | undefined): AgentRole | undefined {
  if (raw === undefined || raw.trim() === "") return undefined;
  const normalized = raw.trim().toUpperCase();
  return isAgentRole(normalized) ? normalized : undefined;
}

export function resolveIdentity(overrides?: IdentityOverrides): TrustedIdentityConfig {
  // The configured static identity is the local/dev principal. It defaults to
  // AGENT (least privilege): operator-level access must be explicit, and the
  // control plane requires enforced credentials anyway.
  const role = overrides?.agentRole ?? resolveRoleOverride(process.env.AGENT_ROLE);
  const agent: AgentIdentity = Object.freeze({
    id: overrides?.agentId ?? process.env.AGENT_ID ?? DEFAULT_AGENT_ID,
    name: overrides?.agentName ?? process.env.AGENT_NAME ?? DEFAULT_AGENT_NAME,
    ...(role !== undefined ? { role } : {}),
  });

  const server: ServerIdentity = Object.freeze({
    id: overrides?.serverId ?? process.env.SERVER_ID ?? DEFAULT_SERVER_ID,
    name: overrides?.serverName ?? process.env.SERVER_NAME ?? DEFAULT_SERVER_NAME,
    upstreamUrl: overrides?.upstreamUrl ?? process.env.UPSTREAM_URL ?? "http://127.0.0.1:3001/mcp",
  });

  return Object.freeze({ agent, server });
}
