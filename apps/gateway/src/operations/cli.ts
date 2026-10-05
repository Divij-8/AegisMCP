/**
 * Operator CLI — local administrative workflows against the same PostgreSQL
 * store the gateway uses.
 *
 * This tool runs WITH database access and is therefore a trusted, out-of-band
 * administrative path (like `psql`). It deliberately does not print secrets:
 * credential hashes/salts are never selected, and approval arguments are only
 * ever the REDACTED copies stored in the database.
 *
 * Commands:
 *   agent create --id <id> [--name <name>] [--role ADMIN|OPERATOR|AUDITOR|AGENT]
 *   agent revoke --id <id>
 *   agent list
 *   policy list
 *   policy create --id <id> --decision <d> --reason <r> [--tool <t>] [--method <m>]
 *                 [--agent <a>] [--server <s>] [--priority <n>]
 *   approval list [--status PENDING|APPROVED|DENIED|EXPIRED] [--agent <id>]
 *   approval approve --id <id> [--reason <text>] [--actor <id>]
 *   approval deny    --id <id> [--reason <text>] [--actor <id>]
 *   audit list [--limit <n>]
 *
 * Usage: node dist/operations/cli.js <group> <command> [flags]
 */

import type { Repositories } from "../repositories/types.js";
import type { ApprovalService } from "../approvals/service.js";
import type { AgentRole } from "../security/rbac.js";
import { isAgentRole } from "../security/rbac.js";
import type { ApprovalStatus } from "../approvals/types.js";
import type { Policy, PolicyDecision } from "../policy/types.js";
import { validatePolicies } from "../policy/validate.js";

export interface CliIo {
  out(line: string): void;
  err(line: string): void;
}

export interface OperationsCliDeps {
  readonly repositories: Repositories;
  readonly approvals: ApprovalService;
  /** Local operator identity recorded as the approver. */
  readonly actorId: string;
}

const DECISIONS: readonly PolicyDecision[] = ["ALLOW", "DENY", "REQUIRE_APPROVAL"];
const STATUSES: readonly ApprovalStatus[] = ["PENDING", "APPROVED", "DENIED", "EXPIRED"];

const USAGE = [
  "AegisMCP operations CLI",
  "",
  "Usage:",
  "  agent create --id <id> [--name <name>] [--role ADMIN|OPERATOR|AUDITOR|AGENT]",
  "  agent revoke --id <id>",
  "  agent list",
  "  policy list",
  "  policy create --id <id> --decision <ALLOW|DENY|REQUIRE_APPROVAL> --reason <r> [--tool <t>] [--method <m>] [--agent <a>] [--server <s>] [--priority <n>]",
  "  approval list [--status <status>] [--agent <id>]",
  "  approval approve --id <id> [--reason <text>] [--actor <id>]",
  "  approval deny    --id <id> [--reason <text>] [--actor <id>]",
  "  audit list [--limit <n>]",
  "",
  "Requires DATABASE_URL. Output never contains secrets.",
].join("\n");

function parseFlags(args: readonly string[]): { flags: Map<string, string>; error?: string } {
  const flags = new Map<string, string>();
  for (let index = 0; index < args.length; index++) {
    const token = args[index]!;
    if (token === "--") continue;
    if (!token.startsWith("--")) return { flags, error: `Unexpected argument "${token}"` };
    const name = token.slice(2);
    const value = args[index + 1];
    if (value === undefined || value.startsWith("--")) {
      return { flags, error: `Missing value for --${name}` };
    }
    flags.set(name, value);
    index++;
  }
  return { flags };
}

function safeMessage(error: unknown): string {
  return error instanceof Error ? error.message : "unknown error";
}

function numberFlag(raw: string | undefined, fallback: number): number {
  if (raw === undefined) return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

export async function runOperationsCli(
  argv: readonly string[],
  io: CliIo,
  deps: OperationsCliDeps,
): Promise<number> {
  const [group, command, ...rest] = argv;

  if (group === undefined || group === "--help" || group === "help") {
    io.out(USAGE);
    return 0;
  }
  if (argv.includes("--help")) {
    io.out(USAGE);
    return 0;
  }

  try {
    if (group === "agent") return await runAgent(command, rest, io, deps);
    if (group === "policy") return await runPolicy(command, rest, io, deps);
    if (group === "approval") return await runApproval(command, rest, io, deps);
    if (group === "audit") return await runAudit(command, rest, io, deps);
    io.err(`Unknown command group "${group}".`);
    io.err(USAGE);
    return 1;
  } catch (error) {
    io.err(`${group} ${command ?? ""} failed: ${safeMessage(error)}`);
    return 1;
  }
}

async function runAgent(
  command: string | undefined,
  args: readonly string[],
  io: CliIo,
  deps: OperationsCliDeps,
): Promise<number> {
  if (command === "create") {
    const { flags, error } = parseFlags(args);
    if (error !== undefined) return usageError(io, "agent create", error);
    const id = flags.get("id");
    if (id === undefined || id.length === 0)
      return usageError(io, "agent create", "--id is required");

    const rawRole = flags.get("role");
    if (rawRole !== undefined && !isAgentRole(rawRole)) {
      return usageError(io, "agent create", "role must be ADMIN, OPERATOR, AUDITOR, or AGENT");
    }
    const role: AgentRole | undefined = rawRole === undefined ? undefined : (rawRole as AgentRole);
    const name = flags.get("name") ?? id;

    await deps.repositories.agents.upsert({
      id,
      name,
      ...(role !== undefined ? { role } : {}),
    });
    const stored = (await deps.repositories.agents.findById(id)) ?? { id, name };
    io.out(`Agent "${stored.id}" registered (role ${stored.role ?? "AGENT"}).`);
    return 0;
  }

  if (command === "revoke") {
    const { flags, error } = parseFlags(args);
    if (error !== undefined) return usageError(io, "agent revoke", error);
    const id = flags.get("id");
    if (id === undefined || id.length === 0)
      return usageError(io, "agent revoke", "--id is required");

    const revoked = await deps.repositories.credentials.revokeAll(id, Date.now());
    io.out(`Revoked ${revoked} credential(s) for agent "${id}".`);
    return 0;
  }

  if (command === "list") {
    const { error } = parseFlags(args);
    if (error !== undefined) return usageError(io, "agent list", error);
    const page = await deps.repositories.agents.list({ limit: 200, offset: 0 });
    if (page.items.length === 0) {
      io.out("No agents registered.");
      return 0;
    }
    io.out(`Agents (${page.total}):`);
    for (const agent of page.items) {
      io.out(`  ${agent.id}  ${agent.name}  role=${agent.role ?? "AGENT"}`);
    }
    return 0;
  }

  return usageError(io, "agent", `unknown command "${command ?? ""}"`);
}

async function runPolicy(
  command: string | undefined,
  args: readonly string[],
  io: CliIo,
  deps: OperationsCliDeps,
): Promise<number> {
  if (command === "list") {
    const page = await deps.repositories.policies.listAll({ limit: 500, offset: 0 });
    if (page.items.length === 0) {
      io.out("No policies configured.");
      return 0;
    }
    io.out(`Policies (${page.total}):`);
    for (const policy of page.items) {
      io.out(
        `  ${policy.id}  ${policy.decision}  priority=${policy.priority ?? 0}` +
          `${policy.enabled === false ? "  [disabled]" : ""}  match=${JSON.stringify(policy.match)}`,
      );
    }
    return 0;
  }

  if (command === "create") {
    const { flags, error } = parseFlags(args);
    if (error !== undefined) return usageError(io, "policy create", error);
    const id = flags.get("id");
    const decision = flags.get("decision");
    const reason = flags.get("reason");
    if (id === undefined || id.length === 0)
      return usageError(io, "policy create", "--id is required");
    if (decision === undefined || !DECISIONS.includes(decision as PolicyDecision)) {
      return usageError(io, "policy create", "--decision must be ALLOW, DENY, or REQUIRE_APPROVAL");
    }
    if (reason === undefined || reason.trim() === "") {
      return usageError(io, "policy create", "--reason is required");
    }

    const match: Policy["match"] = {
      ...(flags.get("tool") !== undefined ? { tool: flags.get("tool")! } : {}),
      ...(flags.get("method") !== undefined ? { method: flags.get("method")! } : {}),
      ...(flags.get("agent") !== undefined ? { agent: flags.get("agent")! } : {}),
      ...(flags.get("server") !== undefined ? { server: flags.get("server")! } : {}),
    };
    const priority = flags.get("priority");

    const policy: Policy = {
      id,
      decision: decision as PolicyDecision,
      match,
      reason,
      ...(priority !== undefined ? { priority: Number(priority) } : {}),
    };
    validatePolicies([policy]);
    await deps.repositories.policies.upsert(policy);
    io.out(
      `Policy "${id}" upserted. Run a policy reload (POST /admin/policies/reload) to activate.`,
    );
    return 0;
  }

  return usageError(io, "policy", `unknown command "${command ?? ""}"`);
}

async function runApproval(
  command: string | undefined,
  args: readonly string[],
  io: CliIo,
  deps: OperationsCliDeps,
): Promise<number> {
  if (command === "list") {
    const { flags, error } = parseFlags(args);
    if (error !== undefined) return usageError(io, "approval list", error);
    const status = flags.get("status");
    if (status !== undefined && !STATUSES.includes(status as ApprovalStatus)) {
      return usageError(io, "approval list", "--status is not a valid approval status");
    }
    await deps.approvals.expireStale();
    const page = await deps.approvals.list(
      {
        ...(status !== undefined ? { status: status as ApprovalStatus } : {}),
        ...(flags.get("agent") !== undefined ? { agentId: flags.get("agent")! } : {}),
      },
      { limit: 200, offset: 0 },
    );
    if (page.items.length === 0) {
      io.out("No approvals.");
      return 0;
    }
    io.out(`Approvals (${page.total}):`);
    for (const approval of page.items) {
      io.out(
        `  ${approval.id}  ${approval.status}  agent=${approval.agentId}  tool=${approval.toolName ?? "-"}`,
      );
    }
    return 0;
  }

  if (command === "approve" || command === "deny") {
    const { flags, error } = parseFlags(args);
    if (error !== undefined) return usageError(io, `approval ${command}`, error);
    const id = flags.get("id");
    if (id === undefined || id.length === 0)
      return usageError(io, `approval ${command}`, "--id is required");
    const actor = flags.get("actor") ?? deps.actorId;
    const reason = flags.get("reason");

    const result =
      command === "approve"
        ? await deps.approvals.approve(id, actor, reason)
        : await deps.approvals.deny(id, actor, reason);

    if (result.kind === "not_found") {
      io.err(`Approval ${id} not found.`);
      return 1;
    }
    if (result.kind === "expired") {
      io.err(`Approval ${id} has expired.`);
      return 1;
    }
    if (result.kind === "already_decided") {
      io.err(`Approval ${id} was already decided.`);
      return 1;
    }
    io.out(`Approval ${id} ${result.kind}.`);
    return 0;
  }

  return usageError(io, "approval", `unknown command "${command ?? ""}"`);
}

async function runAudit(
  command: string | undefined,
  args: readonly string[],
  io: CliIo,
  deps: OperationsCliDeps,
): Promise<number> {
  if (command === "list") {
    const { flags, error } = parseFlags(args);
    if (error !== undefined) return usageError(io, "audit list", error);
    const limit = numberFlag(flags.get("limit"), 50);
    const page = await deps.repositories.auditEvents.list({}, { limit, offset: 0 });
    if (page.items.length === 0) {
      io.out("No audit events.");
      return 0;
    }
    io.out(`Audit events (${page.total}):`);
    for (const event of page.items) {
      io.out(
        `  #${event.id}  ${event.eventType}  ${event.method}  decision=${event.decision ?? "-"}  outcome=${event.outcome}`,
      );
    }
    return 0;
  }

  return usageError(io, "audit", `unknown command "${command ?? ""}"`);
}

function usageError(io: CliIo, scope: string, message: string): number {
  io.err(`${scope}: ${message}`);
  return 1;
}

/* ------------------------------ CLI bootstrap ------------------------------ */

const isCli =
  process.argv[1] != null && import.meta.url === new URL(`file://${process.argv[1]}`).href;

if (isCli) {
  const databaseUrl = process.env.DATABASE_URL;
  if (databaseUrl === undefined || databaseUrl.length === 0) {
    console.error("operations CLI requires DATABASE_URL to be set");
    process.exit(1);
  }

  const { createDbPool, disposeDbPool } = await import("../db/client.js");
  const { runMigrations } = await import("../db/migrate.js");
  const { buildPgRepositories } = await import("../repositories/pg.js");
  const { ApprovalService } = await import("../approvals/service.js");
  const { BufferedAuditSink } = await import("../audit/sink.js");

  const pool = createDbPool(databaseUrl);
  // CLI approval decisions are audited through the same buffered sink as the
  // gateway; close() drains it before the process exits.
  const auditSink = new BufferedAuditSink(buildPgRepositories(pool).auditEvents, {
    flushIntervalMs: 60_000,
  });
  try {
    await runMigrations(pool);
    const repositories = buildPgRepositories(pool);
    const approvals = new ApprovalService(repositories.approvals, auditSink);
    const actorId = process.env.OPERATOR_ID ?? "cli-operator";

    process.exitCode = await runOperationsCli(
      process.argv.slice(2),
      { out: (line) => console.log(line), err: (line) => console.error(line) },
      { repositories, approvals, actorId },
    );
  } catch (error) {
    console.error(
      `operations CLI failed: ${error instanceof Error ? error.message : "unknown error"}`,
    );
    process.exitCode = 1;
  } finally {
    await auditSink.close();
    await disposeDbPool(pool);
  }
}
