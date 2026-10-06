import type { FastifyInstance, FastifyReply } from "fastify";
import { INVALID_REQUEST, INVALID_PARAMS } from "@modelcontextprotocol/server";
import { proxyMcpRequest } from "../proxy/mcp-proxy.js";
import { parseMcpRequest, serializeJsonRpcError } from "../mcp/parse.js";
import type { RequestId, SecurityContext } from "../mcp/types.js";
import type { TrustedIdentityConfig } from "../security/identity.js";
import type { AgentAuthenticator } from "../security/authenticator.js";
import { extractPresentedCredential } from "../security/credential.js";
import type { PolicyStore } from "../policy/store.js";
import type { AuditSink, AuditOutcome, AuthFailureReason } from "../audit/types.js";
import {
  buildRequestAuditEvent,
  buildNotificationAuditEvent,
  buildAuthFailureAuditEvent,
} from "../audit/builder.js";
import type { ApprovalService } from "../approvals/service.js";
import type { RiskEngine } from "../risk/engine.js";
import type { RiskLevel } from "../risk/types.js";
import { METRIC, type Metrics } from "../observability/metrics.js";

export interface McpRuntime {
  /** Live policy store — swapped by app bootstrap when persistence is on. */
  readonly policyStore: PolicyStore;
  /** Live audit sink — swapped by app bootstrap when persistence is on. */
  readonly auditSink: AuditSink;
  /**
   * Authentication gate. Always supplied explicitly so a missing authenticator
   * can never silently disable enforcement.
   */
  readonly authenticator: AgentAuthenticator;
  /**
   * Approval workflow. When persistence is disabled the service is unavailable
   * and REQUIRE_APPROVAL fails closed (never executes, no approval is issued).
   */
  readonly approvalService: ApprovalService;
  /** Risk evaluation applied after policy. Optional; defaults to disabled. */
  readonly riskEngine?: RiskEngine;
  /** In-process counters exposed by the metrics endpoint. */
  readonly metrics: Metrics;
}

export interface McpRoutesOptions {
  upstreamUrl: string;
  upstreamTimeoutMs: number;
  /** Maximum accepted request body size, in bytes. */
  maxRequestBodyBytes: number;
  /** Maximum accepted serialized tool-arguments size, in bytes. */
  maxToolArgumentBytes: number;
  identity: TrustedIdentityConfig;
  /** Mutable holder so bootstrap swaps are visible to every request. */
  runtime: McpRuntime;
}

const DENY_ERROR_CODE = -32003;
const APPROVAL_ERROR_CODE = -32002;
/** Authentication failures are produced by the HTTP security gate, not by policy. */
const AUTH_ERROR_CODE = -32004;
/** Agents present a previously granted approval id on this header. */
const APPROVAL_HEADER = "x-aegis-approval-id";

function firstHeader(value: string | string[] | undefined): string | undefined {
  const raw = Array.isArray(value) ? value[0] : value;
  const trimmed = raw?.trim();
  return trimmed !== undefined && trimmed.length > 0 ? trimmed : undefined;
}

/** Client-facing message for an approval id that cannot authorize execution. */
function approvalRefusalMessage(kind: string): string {
  switch (kind) {
    case "not_found":
      return "Approval not found";
    case "expired":
      return "Approval expired";
    case "already_consumed":
      return "Approval already used";
    case "binding_mismatch":
      return "Approval does not match this request";
    case "not_approved":
    default:
      return "Approval is not approved";
  }
}

function toBuffer(raw: unknown): Buffer {
  if (Buffer.isBuffer(raw)) return raw;
  if (typeof raw === "string") return Buffer.from(raw);
  if (raw != null) return Buffer.from(JSON.stringify(raw));
  return Buffer.alloc(0);
}

function extractNotificationMethod(body: Buffer): string {
  try {
    const parsed: unknown = JSON.parse(body.toString("utf-8"));
    if (
      typeof parsed === "object" &&
      parsed !== null &&
      typeof (parsed as Record<string, unknown>)["method"] === "string"
    ) {
      return (parsed as Record<string, unknown>)["method"] as string;
    }
  } catch {
    // fall through to unknown
  }
  return "unknown";
}

/**
 * Client-facing message. Deliberately generic for every credential problem so
 * the response never becomes a credential-enumeration oracle (unknown vs
 * revoked vs expired vs wrong secret are indistinguishable to the caller).
 */
function authFailureMessage(reason: AuthFailureReason): string {
  if (reason === "missing") return "Missing credentials";
  if (reason === "error") return "Authentication unavailable";
  return "Authentication failed";
}

function sendAuthFailure(
  reply: FastifyReply,
  reason: AuthFailureReason,
  requestId: RequestId | null,
): FastifyReply {
  if (reason === "error") {
    // Infrastructure failure: fail closed, but distinguishably retryable.
    reply.code(503);
  } else {
    reply.code(401);
    if (reason === "missing") reply.header("www-authenticate", "Bearer");
  }
  reply.send(
    serializeJsonRpcError(
      { code: AUTH_ERROR_CODE, message: authFailureMessage(reason) },
      requestId,
    ),
  );
  return reply;
}

export async function mcpRoutes(
  fastify: FastifyInstance,
  options: McpRoutesOptions,
): Promise<void> {
  fastify.removeContentTypeParser("application/json");
  fastify.addContentTypeParser("*", { parseAs: "buffer" }, (_req, body, done) => {
    done(null, body);
  });

  fastify.all("/mcp", async (request, reply) => {
    options.runtime.metrics.increment(METRIC.mcpRequests);

    // JSON-RPC responses are JSON. Fastify serializes a string payload as
    // text/plain by default, which a standards-compliant MCP client (including
    // the official SDK) refuses to parse — turning a policy refusal (-32003), an
    // approval prompt (-32002), or an auth failure (-32004) into an opaque
    // client-side transport error instead of an actionable JSON-RPC error.
    // The proxied path below hijacks the reply and writes the upstream's own
    // headers, so this only affects gateway-generated responses.
    reply.type("application/json");

    const body = toBuffer(request.body);

    // Bound the work before parsing. Fastify also enforces bodyLimit, but this
    // guarantees the behavior for embedded/injected routes too.
    if (body.length > options.maxRequestBodyBytes) {
      reply.code(413);
      reply.send(
        serializeJsonRpcError({ code: INVALID_REQUEST, message: "Request too large" }, null),
      );
      return reply;
    }

    const parseResult = parseMcpRequest(body, options.identity);

    // Normalization failures return before authentication by design: the body
    // carries no actionable content and nothing reaches upstream or policy.
    if (parseResult.kind === "error") {
      reply.code(200);
      reply.send(serializeJsonRpcError(parseResult.error, null));
      return reply;
    }

    // Tool arguments are attacker-controlled; bound them before policy/risk/proxy.
    if (
      parseResult.kind === "request" &&
      parseResult.context.toolArguments !== undefined &&
      JSON.stringify(parseResult.context.toolArguments).length > options.maxToolArgumentBytes
    ) {
      reply.code(200);
      reply.send(
        serializeJsonRpcError({ code: INVALID_PARAMS, message: "Tool arguments too large" }, null),
      );
      return reply;
    }

    const startedAt = Date.now();
    const correlation: { requestId: RequestId | null; method: string } =
      parseResult.kind === "request"
        ? { requestId: parseResult.context.requestId, method: parseResult.context.method }
        : { requestId: null, method: extractNotificationMethod(body) };

    // --- Authentication gate. Strictly before policy evaluation and proxying. ---
    const extraction = extractPresentedCredential({
      authorization: request.headers.authorization,
      apiKey: request.headers["x-api-key"],
    });
    const auth = await options.runtime.authenticator.authenticate(
      extraction.kind === "presented" ? extraction.value : undefined,
    );

    if (!auth.ok) {
      options.runtime.metrics.increment(METRIC.mcpAuthFailures);
      options.runtime.auditSink.record(
        buildAuthFailureAuditEvent({
          requestId: correlation.requestId,
          method: correlation.method,
          occurredAt: startedAt,
          serverId: options.identity.server.id,
          keyId: auth.keyId,
          failureReason: auth.reason,
          latencyMs: Date.now() - startedAt,
        }),
      );
      return sendAuthFailure(reply, auth.reason, correlation.requestId);
    }

    const agent = auth.credential.agent;

    if (parseResult.kind === "notification") {
      let outcome: AuditOutcome = "upstream_error";
      reply.hijack();
      reply.raw.on("finish", () => {
        const status = reply.raw.statusCode;
        outcome =
          status === 502 || status === 504 || status >= 500 ? "upstream_error" : "forwarded";
        options.runtime.auditSink.record(
          buildNotificationAuditEvent({
            method: correlation.method,
            occurredAt: startedAt,
            agentId: agent.id,
            serverId: options.identity.server.id,
            outcome,
            latencyMs: Date.now() - startedAt,
          }),
        );
      });
      proxyMcpRequest(request.raw, reply.raw, body, {
        upstreamUrl: options.upstreamUrl,
        upstreamTimeoutMs: options.upstreamTimeoutMs,
      });
      return new Promise<void>((resolve) => {
        reply.raw.on("finish", () => resolve());
      });
    }

    // Authenticated identity replaces the static placeholder in the context.
    const context: SecurityContext = { ...parseResult.context, agent };
    const engine = options.runtime.policyStore.buildEngine();
    const policyVerdict = engine.evaluate(context);
    // Risk runs AFTER policy and can only strengthen the decision — it can never
    // turn a DENY into an ALLOW or REQUIRE_APPROVAL.
    const riskDecision = options.runtime.riskEngine
      ? options.runtime.riskEngine.apply(context, policyVerdict)
      : { evaluation: policyVerdict, assessment: undefined };
    const verdict = riskDecision.evaluation;
    const riskLevel: RiskLevel | undefined = riskDecision.assessment?.level;
    if (verdict.decision === "ALLOW") options.runtime.metrics.increment(METRIC.mcpPolicyAllow);
    else if (verdict.decision === "DENY") options.runtime.metrics.increment(METRIC.mcpPolicyDeny);
    else options.runtime.metrics.increment(METRIC.mcpPolicyRequireApproval);

    let approvalId: string | undefined;

    if (verdict.decision === "DENY") {
      options.runtime.auditSink.record(
        buildRequestAuditEvent({
          context,
          evaluation: verdict,
          outcome: "blocked",
          upstreamStatus: null,
          latencyMs: Date.now() - startedAt,
          ...(riskLevel !== undefined ? { riskLevel } : {}),
        }),
      );
      reply.code(200);
      reply.send(
        serializeJsonRpcError(
          { code: DENY_ERROR_CODE, message: verdict.reason },
          context.requestId,
        ),
      );
      return reply;
    }

    if (verdict.decision === "REQUIRE_APPROVAL") {
      const presented = firstHeader(request.headers[APPROVAL_HEADER]);

      if (presented !== undefined) {
        // An approval authorizes execution only when it is APPROVED, unexpired,
        // unconsumed, and bound to THIS exact request. Otherwise fail closed.
        const consumed = await options.runtime.approvalService.consume(
          presented,
          context,
          agent.id,
        );
        if (consumed.kind !== "ok") {
          options.runtime.auditSink.record(
            buildRequestAuditEvent({
              context,
              evaluation: verdict,
              outcome: "blocked",
              upstreamStatus: null,
              latencyMs: Date.now() - startedAt,
              approvalId: presented,
              ...(riskLevel !== undefined ? { riskLevel } : {}),
            }),
          );
          reply.code(200);
          reply.send(
            serializeJsonRpcError(
              { code: APPROVAL_ERROR_CODE, message: approvalRefusalMessage(consumed.kind) },
              context.requestId,
            ),
          );
          return reply;
        }
        approvalId = consumed.approval.id;
        options.runtime.metrics.increment(METRIC.approvalsConsumed);
      } else {
        // No approval presented: create/reuse a PENDING approval. Nothing executes.
        const created = await options.runtime.approvalService.createForContext(context, verdict);
        const createdId = created.kind === "unavailable" ? undefined : created.approval.id;
        options.runtime.auditSink.record(
          buildRequestAuditEvent({
            context,
            evaluation: verdict,
            outcome: "blocked",
            upstreamStatus: null,
            latencyMs: Date.now() - startedAt,
            ...(createdId !== undefined ? { approvalId: createdId } : {}),
            ...(riskLevel !== undefined ? { riskLevel } : {}),
          }),
        );
        reply.code(200);
        if (created.kind === "unavailable") {
          // Fail closed: no approval can be issued, so nothing can authorize
          // execution. The client still sees the policy's reason (unchanged
          // contract); the absence of an approval id signals unavailability.
          reply.send(
            serializeJsonRpcError(
              { code: APPROVAL_ERROR_CODE, message: verdict.reason },
              context.requestId,
            ),
          );
        } else {
          reply.send(
            serializeJsonRpcError(
              {
                code: APPROVAL_ERROR_CODE,
                message: verdict.reason,
                data: {
                  approvalId: created.approval.id,
                  status: created.approval.status,
                  expiresAt: created.approval.expiresAt,
                },
              },
              context.requestId,
            ),
          );
        }
        return reply;
      }
    }

    let outcome: AuditOutcome = "upstream_error";
    let upstreamStatus: number | null = null;
    reply.hijack();
    reply.raw.on("finish", () => {
      const status = reply.raw.statusCode;
      upstreamStatus = status >= 500 ? null : status;
      if (status === 502 || status === 504) outcome = "upstream_error";
      else if (status >= 500) outcome = "upstream_error";
      else outcome = "forwarded";
      if (outcome === "upstream_error") options.runtime.metrics.increment(METRIC.mcpUpstreamErrors);
      if (status === 504) options.runtime.metrics.increment(METRIC.mcpUpstreamTimeouts);
      options.runtime.auditSink.record(
        buildRequestAuditEvent({
          context,
          evaluation: verdict,
          outcome,
          upstreamStatus,
          latencyMs: Date.now() - startedAt,
          ...(approvalId !== undefined ? { approvalId } : {}),
          ...(riskLevel !== undefined ? { riskLevel } : {}),
        }),
      );
    });
    proxyMcpRequest(request.raw, reply.raw, body, {
      upstreamUrl: options.upstreamUrl,
      upstreamTimeoutMs: options.upstreamTimeoutMs,
    });
    return new Promise<void>((resolve) => {
      reply.raw.on("finish", () => resolve());
    });
  });
}
