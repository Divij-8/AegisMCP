/**
 * Control-plane (administrative) API.
 *
 * Mounted under /admin and kept strictly separate from the data plane (/mcp):
 * an ordinary agent credential can never reach these routes because every
 * handler requires an explicit permission that only privileged roles hold.
 *
 * Guarantees:
 * - Authentication is enforced (an unenforced/dev authenticator is refused).
 * - Authorization is permission-based (see security/rbac.ts), never a role
 *   string check scattered in a handler.
 * - Every request is validated, paginated, and answered with a consistent
 *   { error: { code, message, requestId } } shape on failure.
 * - Every accepted operation is audited; failures to authorize are audited too.
 * - Responses never contain credential hashes, salts, peppers, or raw secrets.
 */

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { extractPresentedCredential } from "../security/credential.js";
import {
  hasPermission,
  isAgentRole,
  permissionsFor,
  PRIVILEGED_ROLES,
  resolveRole,
  type AgentRole,
  type Permission,
} from "../security/rbac.js";
import type { AgentIdentity } from "../security/identity.js";
import type { Policy } from "../policy/types.js";
import { validatePolicies } from "../policy/validate.js";
import type { Persistence } from "../persistence/bootstrap.js";
import type { AuditListFilter, PageQuery } from "../repositories/types.js";
import type { McpRuntime } from "./mcp.js";
import { buildAdminAuditEvent, buildAuthFailureAuditEvent } from "../audit/builder.js";
import { METRIC } from "../observability/metrics.js";
import type { ApprovalStatus } from "../approvals/types.js";

export interface AdminRoutesOptions {
  readonly runtime: McpRuntime;
  readonly getPersistence: () => Persistence | null;
}

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;

const APPROVAL_STATUSES: readonly ApprovalStatus[] = ["PENDING", "APPROVED", "DENIED", "EXPIRED"];

interface Principal {
  readonly agent: AgentIdentity;
  readonly keyId: string;
}

function errorBody(code: string, message: string, requestId: string): unknown {
  return { error: { code, message, requestId } };
}

function fail(
  reply: FastifyReply,
  status: number,
  code: string,
  message: string,
  requestId: string,
): null {
  reply.code(status).send(errorBody(code, message, requestId));
  return null;
}

function requestIdOf(request: FastifyRequest): string {
  return String(request.id);
}

function parsePage(request: FastifyRequest): PageQuery | { readonly error: string } {
  const query = request.query as Record<string, unknown>;
  const rawLimit = query["limit"];
  const rawOffset = query["offset"];

  let limit = DEFAULT_LIMIT;
  if (rawLimit !== undefined) {
    const parsed = Number(rawLimit);
    if (!Number.isInteger(parsed) || parsed < 1 || parsed > MAX_LIMIT) {
      return { error: `limit must be an integer between 1 and ${MAX_LIMIT}` };
    }
    limit = parsed;
  }

  let offset = 0;
  if (rawOffset !== undefined) {
    const parsed = Number(rawOffset);
    if (!Number.isInteger(parsed) || parsed < 0) {
      return { error: "offset must be a non-negative integer" };
    }
    offset = parsed;
  }

  return { limit, offset };
}

function queryString(request: FastifyRequest, key: string): string | undefined {
  const value = (request.query as Record<string, unknown>)[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

/**
 * Authenticate and authorize a control-plane request.
 *
 * Returns the principal when the caller holds `permission`; otherwise sends the
 * appropriate error and returns null. Fails closed when the control plane cannot
 * be backed by real authentication/authorization.
 */
async function authorize(
  request: FastifyRequest,
  reply: FastifyReply,
  options: AdminRoutesOptions,
  permission: Permission,
  serverId: string,
): Promise<Principal | null> {
  const persistence = options.getPersistence();
  const requestId = requestIdOf(request);
  options.runtime.metrics.increment(METRIC.adminRequests);

  if (persistence === null) {
    return fail(
      reply,
      503,
      "control_plane_unavailable",
      "Control plane requires PostgreSQL persistence",
      requestId,
    );
  }
  if (!options.runtime.authenticator.enforced) {
    return fail(
      reply,
      403,
      "admin_auth_required",
      "Administrative authentication is not enabled",
      requestId,
    );
  }

  const extraction = extractPresentedCredential({
    authorization: request.headers.authorization,
    apiKey: request.headers["x-api-key"],
  });
  const auth = await options.runtime.authenticator.authenticate(
    extraction.kind === "presented" ? extraction.value : undefined,
  );

  if (!auth.ok) {
    options.runtime.metrics.increment(METRIC.adminAuthFailures);
    options.runtime.auditSink.record(
      buildAuthFailureAuditEvent({
        requestId: null,
        method: `admin.${request.method} ${request.url}`,
        occurredAt: Date.now(),
        serverId,
        keyId: auth.keyId,
        failureReason: auth.reason,
        latencyMs: 0,
      }),
    );
    const status = auth.reason === "error" ? 503 : 401;
    return fail(reply, status, "unauthorized", "Authentication failed", requestId);
  }

  // Re-read the principal so a role change takes effect immediately and a
  // deleted agent cannot keep operating from a stale credential snapshot.
  const agent =
    (await persistence.repositories.agents.findById(auth.credential.agent.id)) ??
    auth.credential.agent;

  if (!hasPermission(agent, permission)) {
    options.runtime.auditSink.record(
      buildAdminAuditEvent({
        action: `denied:${permission}`,
        outcome: "blocked",
        actorId: agent.id,
        serverId,
        occurredAt: Date.now(),
        latencyMs: 0,
        detail: `missing permission ${permission}`,
      }),
    );
    return fail(reply, 403, "forbidden", "Insufficient permissions", requestId);
  }

  return { agent, keyId: auth.credential.keyId };
}

function auditAdmin(
  options: AdminRoutesOptions,
  principal: Principal,
  serverId: string,
  action: string,
  detail?: string,
): void {
  options.runtime.auditSink.record(
    buildAdminAuditEvent({
      action,
      outcome: "forwarded",
      actorId: principal.agent.id,
      serverId,
      occurredAt: Date.now(),
      latencyMs: 0,
      ...(detail !== undefined ? { detail } : {}),
    }),
  );
}

/** Validate a policy definition coming from an untrusted request body. */
function parsePolicy(
  body: unknown,
  idOverride?: string,
): { readonly policy: Policy } | { readonly error: string } {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return { error: "body must be a JSON object" };
  }
  const raw = body as Record<string, unknown>;
  const id = idOverride ?? raw["id"];
  if (typeof id !== "string" || id.trim() === "") {
    return { error: "id must be a non-empty string" };
  }
  if (!["ALLOW", "DENY", "REQUIRE_APPROVAL"].includes(raw["decision"] as string)) {
    return { error: "decision must be ALLOW, DENY, or REQUIRE_APPROVAL" };
  }
  if (typeof raw["reason"] !== "string" || raw["reason"].trim() === "") {
    return { error: "reason must be a non-empty string" };
  }
  const match = raw["match"] ?? {};
  if (typeof match !== "object" || match === null || Array.isArray(match)) {
    return { error: "match must be an object" };
  }
  for (const field of ["agent", "server", "method", "tool"] as const) {
    const value = (match as Record<string, unknown>)[field];
    if (value !== undefined && typeof value !== "string") {
      return { error: `match.${field} must be a string` };
    }
  }
  const priority = raw["priority"];
  if (priority !== undefined && (typeof priority !== "number" || !Number.isFinite(priority))) {
    return { error: "priority must be a number" };
  }
  const enabled = raw["enabled"];
  if (enabled !== undefined && typeof enabled !== "boolean") {
    return { error: "enabled must be a boolean" };
  }

  const policy: Policy & { enabled?: boolean } = {
    id,
    decision: raw["decision"] as Policy["decision"],
    match: match as Policy["match"],
    reason: raw["reason"] as string,
    ...(priority !== undefined ? { priority: priority as number } : {}),
    ...(enabled !== undefined ? { enabled: enabled as boolean } : {}),
  };

  try {
    validatePolicies([policy]);
  } catch (error) {
    return { error: error instanceof Error ? error.message : "invalid policy" };
  }
  return { policy };
}

export async function adminRoutes(
  fastify: FastifyInstance,
  options: AdminRoutesOptions,
): Promise<void> {
  fastify.addHook("onSend", async (request, reply, payload) => {
    reply.header("x-request-id", requestIdOf(request));
    return payload;
  });

  const resolveServerId = (persistence: Persistence): string => {
    // Any registered server satisfies the audit FK; the gateway's own identity
    // is registered at boot. Prefer that one when present.
    return persistence.identity.server.id;
  };

  /** Shared auth+audit wrapper for control-plane handlers. */
  const guard = async (
    request: FastifyRequest,
    reply: FastifyReply,
    permission: Permission,
  ): Promise<Principal | null> => {
    const persistence = options.getPersistence();
    const serverId = persistence !== null ? resolveServerId(persistence) : "unknown";
    return authorize(request, reply, options, permission, serverId);
  };

  /* ------------------------------- approvals ------------------------------ */

  fastify.get("/admin/approvals", async (request, reply) => {
    const principal = await guard(request, reply, "approval:read");
    if (principal === null) return reply;
    const persistence = options.getPersistence()!;
    const page = parsePage(request);
    if ("error" in page) {
      return fail(reply, 400, "invalid_query", page.error, requestIdOf(request));
    }

    // Reading the queue also expires what is past its deadline (audited).
    await options.runtime.approvalService.expireStale();

    const status = queryString(request, "status");
    if (status !== undefined && !APPROVAL_STATUSES.includes(status as ApprovalStatus)) {
      return fail(
        reply,
        400,
        "invalid_query",
        "status is not a valid approval status",
        requestIdOf(request),
      );
    }
    const filter = {
      ...(status !== undefined ? { status: status as ApprovalStatus } : {}),
      ...(queryString(request, "agentId") !== undefined
        ? { agentId: queryString(request, "agentId")! }
        : {}),
      ...(queryString(request, "serverId") !== undefined
        ? { serverId: queryString(request, "serverId")! }
        : {}),
    };
    const result = await options.runtime.approvalService.list(filter, page);
    auditAdmin(options, principal, resolveServerId(persistence), "approval.list");
    return reply.send(result);
  });

  fastify.get<{ Params: { id: string } }>("/admin/approvals/:id", async (request, reply) => {
    const principal = await guard(request, reply, "approval:read");
    if (principal === null) return reply;
    const approval = await options.runtime.approvalService.getById(request.params.id);
    if (approval === null) {
      return fail(reply, 404, "not_found", "Approval not found", requestIdOf(request));
    }
    auditAdmin(options, principal, resolveServerId(options.getPersistence()!), "approval.get");
    return reply.send(approval);
  });

  fastify.post<{ Params: { id: string } }>(
    "/admin/approvals/:id/approve",
    async (request, reply) => {
      const principal = await guard(request, reply, "approval:decide");
      if (principal === null) return reply;
      const reason = readReason(request.body);
      const result = await options.runtime.approvalService.approve(
        request.params.id,
        principal.agent.id,
        reason,
      );
      return finishDecision(
        reply,
        request,
        principal,
        options,
        result,
        "approval.approve",
        resolveServerId(options.getPersistence()!),
      );
    },
  );

  fastify.post<{ Params: { id: string } }>("/admin/approvals/:id/deny", async (request, reply) => {
    const principal = await guard(request, reply, "approval:decide");
    if (principal === null) return reply;
    const reason = readReason(request.body);
    const result = await options.runtime.approvalService.deny(
      request.params.id,
      principal.agent.id,
      reason,
    );
    return finishDecision(
      reply,
      request,
      principal,
      options,
      result,
      "approval.deny",
      resolveServerId(options.getPersistence()!),
    );
  });

  /* ------------------------------- policies ------------------------------- */

  fastify.get("/admin/policies", async (request, reply) => {
    const principal = await guard(request, reply, "policy:read");
    if (principal === null) return reply;
    const persistence = options.getPersistence()!;
    const page = parsePage(request);
    if ("error" in page) return fail(reply, 400, "invalid_query", page.error, requestIdOf(request));
    const result = await persistence.repositories.policies.listAll(page);
    auditAdmin(options, principal, resolveServerId(persistence), "policy.list");
    return reply.send(result);
  });

  fastify.get<{ Params: { id: string } }>("/admin/policies/:id", async (request, reply) => {
    const principal = await guard(request, reply, "policy:read");
    if (principal === null) return reply;
    const persistence = options.getPersistence()!;
    const policy = await persistence.repositories.policies.findById(request.params.id);
    if (policy === null) {
      return fail(reply, 404, "not_found", "Policy not found", requestIdOf(request));
    }
    auditAdmin(options, principal, resolveServerId(persistence), "policy.get");
    return reply.send(policy);
  });

  fastify.post("/admin/policies", async (request, reply) => {
    const principal = await guard(request, reply, "policy:write");
    if (principal === null) return reply;
    const persistence = options.getPersistence()!;
    const parsed = parsePolicy(request.body);
    if ("error" in parsed) {
      return fail(reply, 400, "invalid_policy", parsed.error, requestIdOf(request));
    }
    await persistence.repositories.policies.upsert(parsed.policy);
    options.runtime.metrics.increment(METRIC.policyReloads);
    const changed = await options.runtime.policyStore.reload();
    auditAdmin(options, principal, resolveServerId(persistence), "policy.create", parsed.policy.id);
    return reply.code(201).send({ policy: parsed.policy, reloaded: changed });
  });

  fastify.patch<{ Params: { id: string } }>("/admin/policies/:id", async (request, reply) => {
    const principal = await guard(request, reply, "policy:write");
    if (principal === null) return reply;
    const persistence = options.getPersistence()!;
    const existing = await persistence.repositories.policies.findById(request.params.id);
    if (existing === null) {
      return fail(reply, 404, "not_found", "Policy not found", requestIdOf(request));
    }
    if (typeof request.body !== "object" || request.body === null) {
      return fail(reply, 400, "invalid_policy", "body must be a JSON object", requestIdOf(request));
    }
    const patch = request.body as Record<string, unknown>;
    const merged = { ...existing, ...patch, id: existing.id };
    const parsed = parsePolicy(merged, existing.id);
    if ("error" in parsed) {
      return fail(reply, 400, "invalid_policy", parsed.error, requestIdOf(request));
    }
    await persistence.repositories.policies.upsert(parsed.policy);
    const changed = await options.runtime.policyStore.reload();
    auditAdmin(options, principal, resolveServerId(persistence), "policy.update", parsed.policy.id);
    return reply.send({ policy: parsed.policy, reloaded: changed });
  });

  fastify.delete<{ Params: { id: string } }>("/admin/policies/:id", async (request, reply) => {
    const principal = await guard(request, reply, "policy:write");
    if (principal === null) return reply;
    const persistence = options.getPersistence()!;
    const removed = await persistence.repositories.policies.remove(request.params.id);
    if (!removed) {
      return fail(reply, 404, "not_found", "Policy not found", requestIdOf(request));
    }
    const changed = await options.runtime.policyStore.reload();
    auditAdmin(
      options,
      principal,
      resolveServerId(persistence),
      "policy.delete",
      request.params.id,
    );
    return reply.send({ deleted: request.params.id, reloaded: changed });
  });

  fastify.post("/admin/policies/reload", async (request, reply) => {
    const principal = await guard(request, reply, "policy:write");
    if (principal === null) return reply;
    const persistence = options.getPersistence()!;
    options.runtime.metrics.increment(METRIC.policyReloads);
    const changed = await options.runtime.policyStore.reload();
    auditAdmin(options, principal, resolveServerId(persistence), "policy.reload");
    return reply.send({ reloaded: true, changed });
  });

  /* -------------------------------- agents -------------------------------- */

  fastify.get("/admin/agents", async (request, reply) => {
    const principal = await guard(request, reply, "agent:read");
    if (principal === null) return reply;
    const persistence = options.getPersistence()!;
    const page = parsePage(request);
    if ("error" in page) return fail(reply, 400, "invalid_query", page.error, requestIdOf(request));
    const result = await persistence.repositories.agents.list(page);
    auditAdmin(options, principal, resolveServerId(persistence), "agent.list");
    return reply.send(result);
  });

  fastify.get<{ Params: { id: string } }>("/admin/agents/:id", async (request, reply) => {
    const principal = await guard(request, reply, "agent:read");
    if (principal === null) return reply;
    const persistence = options.getPersistence()!;
    const agent = await persistence.repositories.agents.findById(request.params.id);
    if (agent === null) {
      return fail(reply, 404, "not_found", "Agent not found", requestIdOf(request));
    }
    auditAdmin(options, principal, resolveServerId(persistence), "agent.get", agent.id);
    return reply.send(agent);
  });

  fastify.post("/admin/agents", async (request, reply) => {
    const principal = await guard(request, reply, "agent:manage");
    if (principal === null) return reply;
    const persistence = options.getPersistence()!;
    if (typeof request.body !== "object" || request.body === null) {
      return fail(reply, 400, "invalid_agent", "body must be a JSON object", requestIdOf(request));
    }
    const raw = request.body as Record<string, unknown>;
    if (typeof raw["id"] !== "string" || raw["id"].trim() === "") {
      return fail(
        reply,
        400,
        "invalid_agent",
        "id must be a non-empty string",
        requestIdOf(request),
      );
    }
    let role: AgentRole | undefined;
    if (raw["role"] !== undefined) {
      if (typeof raw["role"] !== "string" || !isAgentRole(raw["role"])) {
        return fail(
          reply,
          400,
          "invalid_agent",
          "role must be one of ADMIN, OPERATOR, AUDITOR, AGENT",
          requestIdOf(request),
        );
      }
      role = raw["role"];
    }

    // Assigning a privileged role is ADMIN-only: otherwise an OPERATOR could
    // mint an ADMIN/OPERATOR principal (privilege escalation).
    if (
      role !== undefined &&
      PRIVILEGED_ROLES.includes(role) &&
      !hasPermission(principal.agent, "role:assign")
    ) {
      options.runtime.auditSink.record(
        buildAdminAuditEvent({
          action: "denied:role:assign",
          outcome: "blocked",
          actorId: principal.agent.id,
          serverId: resolveServerId(persistence),
          occurredAt: Date.now(),
          latencyMs: 0,
          detail: `attempted to assign role ${role}`,
        }),
      );
      return fail(
        reply,
        403,
        "forbidden",
        "Insufficient permissions to assign a privileged role",
        requestIdOf(request),
      );
    }

    const name =
      typeof raw["name"] === "string" && raw["name"].trim() !== "" ? raw["name"] : raw["id"];
    const agent: AgentIdentity = { id: raw["id"], name, ...(role !== undefined ? { role } : {}) };
    await persistence.repositories.agents.upsert(agent);
    const stored = (await persistence.repositories.agents.findById(agent.id)) ?? agent;
    auditAdmin(options, principal, resolveServerId(persistence), "agent.create", agent.id);
    return reply.code(201).send(stored);
  });

  fastify.post<{ Params: { id: string } }>("/admin/agents/:id/revoke", async (request, reply) => {
    const principal = await guard(request, reply, "agent:manage");
    if (principal === null) return reply;
    const persistence = options.getPersistence()!;
    const exists = await persistence.repositories.agents.exists(request.params.id);
    if (!exists) {
      return fail(reply, 404, "not_found", "Agent not found", requestIdOf(request));
    }
    // Revocation disables every active credential for the agent. The agent
    // registry row is kept so audit history and identity remain resolvable.
    const revoked = await persistence.repositories.credentials.revokeAll(
      request.params.id,
      Date.now(),
    );
    auditAdmin(
      options,
      principal,
      resolveServerId(persistence),
      "agent.revoke",
      `${request.params.id} (${revoked} credential(s))`,
    );
    return reply.send({ agentId: request.params.id, revokedCredentials: revoked });
  });

  /* -------------------------------- servers ------------------------------- */

  fastify.get("/admin/servers", async (request, reply) => {
    const principal = await guard(request, reply, "server:read");
    if (principal === null) return reply;
    const persistence = options.getPersistence()!;
    const page = parsePage(request);
    if ("error" in page) return fail(reply, 400, "invalid_query", page.error, requestIdOf(request));
    const result = await persistence.repositories.servers.list(page);
    auditAdmin(options, principal, resolveServerId(persistence), "server.list");
    return reply.send(result);
  });

  fastify.get<{ Params: { id: string } }>("/admin/servers/:id", async (request, reply) => {
    const principal = await guard(request, reply, "server:read");
    if (principal === null) return reply;
    const persistence = options.getPersistence()!;
    const server = await persistence.repositories.servers.findById(request.params.id);
    if (server === null) {
      return fail(reply, 404, "not_found", "Server not found", requestIdOf(request));
    }
    auditAdmin(options, principal, resolveServerId(persistence), "server.get", server.id);
    return reply.send(server);
  });

  /* --------------------------------- audit -------------------------------- */

  fastify.get("/admin/audit", async (request, reply) => {
    const principal = await guard(request, reply, "audit:read");
    if (principal === null) return reply;
    const persistence = options.getPersistence()!;
    const page = parsePage(request);
    if ("error" in page) return fail(reply, 400, "invalid_query", page.error, requestIdOf(request));
    const filter = parseAuditFilter(request);
    if ("error" in filter) {
      return fail(reply, 400, "invalid_query", filter.error, requestIdOf(request));
    }
    const result = await persistence.repositories.auditEvents.list(filter, page);
    auditAdmin(options, principal, resolveServerId(persistence), "audit.list");
    return reply.send(result);
  });

  fastify.get<{ Params: { id: string } }>("/admin/audit/:id", async (request, reply) => {
    const principal = await guard(request, reply, "audit:read");
    if (principal === null) return reply;
    const persistence = options.getPersistence()!;
    const event = await persistence.repositories.auditEvents.findById(request.params.id);
    if (event === null) {
      return fail(reply, 404, "not_found", "Audit event not found", requestIdOf(request));
    }
    auditAdmin(options, principal, resolveServerId(persistence), "audit.get", event.id);
    return reply.send(event);
  });

  /* ------------------------------ self describe ---------------------------- */

  fastify.get("/admin/me", async (request, reply) => {
    const principal = await guard(request, reply, "approval:read");
    if (principal === null) return reply;
    return reply.send({
      agent: principal.agent,
      role: resolveRole(principal.agent),
      permissions: permissionsFor(resolveRole(principal.agent)),
    });
  });
}

function readReason(body: unknown): string | undefined {
  if (typeof body !== "object" || body === null) return undefined;
  const reason = (body as Record<string, unknown>)["reason"];
  return typeof reason === "string" && reason.length > 0 ? reason.slice(0, 500) : undefined;
}

function parseAuditFilter(request: FastifyRequest): AuditListFilter | { readonly error: string } {
  const filter: {
    eventType?: string;
    agentId?: string;
    serverId?: string;
    decision?: string;
    outcome?: string;
    approvalId?: string;
    since?: number;
    until?: number;
  } = {};
  for (const key of [
    "eventType",
    "agentId",
    "serverId",
    "decision",
    "outcome",
    "approvalId",
  ] as const) {
    const value = queryString(request, key);
    if (value !== undefined) filter[key] = value;
  }
  for (const key of ["since", "until"] as const) {
    const value = queryString(request, key);
    if (value !== undefined) {
      const parsed = Number(value);
      if (!Number.isFinite(parsed)) return { error: `${key} must be an epoch-millis number` };
      filter[key] = parsed;
    }
  }
  return filter;
}

function finishDecision(
  reply: FastifyReply,
  request: FastifyRequest,
  principal: Principal,
  options: AdminRoutesOptions,
  result: Awaited<ReturnType<McpRuntime["approvalService"]["approve"]>>,
  action: string,
  serverId: string,
): FastifyReply {
  if (result.kind === "not_found") {
    return reply.code(404).send(errorBody("not_found", "Approval not found", requestIdOf(request)));
  }
  if (result.kind === "expired") {
    return reply.code(409).send(errorBody("expired", "Approval has expired", requestIdOf(request)));
  }
  if (result.kind === "already_decided") {
    return reply
      .code(409)
      .send(errorBody("already_decided", "Approval was already decided", requestIdOf(request)));
  }
  options.runtime.metrics.increment(
    result.kind === "approved" ? METRIC.approvalsApproved : METRIC.approvalsDenied,
  );
  auditAdmin(options, principal, serverId, action, result.approval.id);
  return reply.send(result.approval);
}
