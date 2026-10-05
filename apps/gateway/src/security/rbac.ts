/**
 * Role-based access control for the control plane.
 *
 * Roles are attached to authenticated principals (agents) and map to a fixed
 * permission set. Authorization is expressed as permissions, never as scattered
 * role string comparisons, so adding an endpoint means declaring the permission
 * it requires.
 *
 * Fail-closed: an unknown or missing role is treated as AGENT, which holds no
 * control-plane permission.
 */

export const AGENT_ROLES = ["ADMIN", "OPERATOR", "AUDITOR", "AGENT"] as const;

export type AgentRole = (typeof AGENT_ROLES)[number];

export const PERMISSIONS = [
  "approval:read",
  "approval:decide",
  "policy:read",
  "policy:write",
  "agent:read",
  "agent:manage",
  "server:read",
  "audit:read",
  //
  // ADMIN-ONLY: assigning a privileged role (ADMIN/OPERATOR/AUDITOR) to a
  // principal. Without this separate permission an OPERATOR could mint an
  // ADMIN/OPERATOR principal — a privilege-escalation path. Ordinary AGENT
  // principals can be created with `agent:manage` alone.
  "role:assign",
] as const;

export type Permission = (typeof PERMISSIONS)[number];

const READ_ONLY: readonly Permission[] = [
  "approval:read",
  "policy:read",
  "agent:read",
  "server:read",
  "audit:read",
];

const ROLE_PERMISSIONS: Record<AgentRole, readonly Permission[]> = {
  // ADMIN holds every permission, including the ADMIN-only role:assign.
  ADMIN: PERMISSIONS,
  OPERATOR: [...READ_ONLY, "approval:decide", "policy:write", "agent:manage"],
  AUDITOR: READ_ONLY,
  // Ordinary MCP agents are data-plane only: no control-plane permissions.
  AGENT: [],
};

/** Role assignment requires the ADMIN-only permission for privileged roles. */
export const PRIVILEGED_ROLES: readonly AgentRole[] = ["ADMIN", "OPERATOR", "AUDITOR"];

export function isAgentRole(value: string): value is AgentRole {
  return (AGENT_ROLES as readonly string[]).includes(value);
}

/** Role of a principal. Missing/unknown roles fall back to the safest role. */
export function resolveRole(principal: { readonly role?: AgentRole }): AgentRole {
  return principal.role ?? "AGENT";
}

export function permissionsFor(role: AgentRole): readonly Permission[] {
  return ROLE_PERMISSIONS[role];
}

export function hasPermission(
  principal: { readonly role?: AgentRole },
  permission: Permission,
): boolean {
  return ROLE_PERMISSIONS[resolveRole(principal)].includes(permission);
}
