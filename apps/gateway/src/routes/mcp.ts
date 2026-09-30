import type { FastifyInstance, FastifyReply } from "fastify";
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
}

export interface McpRoutesOptions {
  upstreamUrl: string;
  upstreamTimeoutMs: number;
  identity: TrustedIdentityConfig;
  /** Mutable holder so bootstrap swaps are visible to every request. */
  runtime: McpRuntime;
}

const DENY_ERROR_CODE = -32003;
const APPROVAL_ERROR_CODE = -32002;
/** Authentication failures are produced by the HTTP security gate, not by policy. */
const AUTH_ERROR_CODE = -32004;

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
    const body = toBuffer(request.body);
    const parseResult = parseMcpRequest(body, options.identity);

    // Normalization failures return before authentication by design: the body
    // carries no actionable content and nothing reaches upstream or policy.
    if (parseResult.kind === "error") {
      reply.code(200);
      reply.send(serializeJsonRpcError(parseResult.error, null));
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
    const verdict = engine.evaluate(context);

    if (verdict.decision === "DENY" || verdict.decision === "REQUIRE_APPROVAL") {
      const code = verdict.decision === "DENY" ? DENY_ERROR_CODE : APPROVAL_ERROR_CODE;
      options.runtime.auditSink.record(
        buildRequestAuditEvent({
          context,
          evaluation: verdict,
          outcome: "blocked",
          upstreamStatus: null,
          latencyMs: Date.now() - startedAt,
        }),
      );
      reply.code(200);
      reply.send(serializeJsonRpcError({ code, message: verdict.reason }, context.requestId));
      return reply;
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
      options.runtime.auditSink.record(
        buildRequestAuditEvent({
          context,
          evaluation: verdict,
          outcome,
          upstreamStatus,
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
  });
}
