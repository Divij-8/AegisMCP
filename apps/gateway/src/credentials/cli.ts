/**
 * Credential administration CLI.
 *
 * Commands:
 *   create --agent <id> [--agent-name <name>] [--label <label>] [--expires-in-days <n>]
 *   revoke --key-id <id>
 *   list   --agent <id>
 *
 * Security: `create` prints the plaintext API key EXACTLY ONCE and never
 * persists or logs it. Every other output path (errors, usage, list, revoke)
 * contains only public key ids. The plaintext value is never attached to an
 * error, and failure messages are reduced to a message string so a raw error
 * object (which could carry driver detail) is never dumped.
 *
 * Usage: node dist/credentials/cli.js <command> [flags]
 *        pnpm --filter @aegis/gateway credential:create -- ...
 */

import type { CredentialService } from "../security/credential-service.js";
import { DefaultCredentialService } from "../security/credential-service.js";
import { ScryptSecretHasher } from "../security/hash.js";

export interface CliIo {
  out(line: string): void;
  err(line: string): void;
}

export interface CredentialCliDeps {
  readonly service: CredentialService;
}

const USAGE = [
  "AegisMCP credential administration",
  "",
  "Usage:",
  "  credential create --agent <id> [--agent-name <name>] [--label <label>] [--expires-in-days <n>]",
  "  credential revoke --key-id <id>",
  "  credential list   --agent <id>",
  "",
  "Roles are not assigned here: a new agent defaults to AGENT. Assign a role with",
  "  operations agent create --id <id> --role ADMIN|OPERATOR|AUDITOR|AGENT",
  "",
  "Requires DATABASE_URL. The API key is printed once on creation and is never stored.",
].join("\n");

interface ParsedFlags {
  readonly flags: Map<string, string>;
  readonly error: string | undefined;
}

function supportedFlags(allowed: readonly string[]): string {
  return allowed.length === 0
    ? "This command accepts no flags."
    : `Supported flags: ${allowed.map((flag) => `--${flag}`).join(", ")}`;
}

/**
 * Parse `--flag value` pairs, rejecting anything outside `allowed`.
 *
 * Unknown flags fail loudly on purpose. Silently dropping one let
 * `credential:create --agent my-agent --role OPERATOR` report success while
 * registering an AGENT-role principal, so the caller's next control-plane
 * request failed with 403 and nothing explained why. Roles are owned by
 * `operations agent create --role`; the error message points at the flags
 * this command really takes.
 */
function parseFlags(args: readonly string[], allowed: readonly string[]): ParsedFlags {
  const flags = new Map<string, string>();
  for (let index = 0; index < args.length; index++) {
    const token = args[index]!;
    // Tolerate the "--" delimiter that package managers forward verbatim.
    if (token === "--") continue;
    if (!token.startsWith("--")) {
      return { flags, error: `Unexpected argument "${token}"` };
    }
    const name = token.slice(2);
    if (!allowed.includes(name)) {
      return { flags, error: `Unknown flag "--${name}". ${supportedFlags(allowed)}` };
    }
    const value = args[index + 1];
    if (value === undefined || value.startsWith("--")) {
      return { flags, error: `Missing value for --${name}` };
    }
    flags.set(name, value);
    index++;
  }
  return { flags, error: undefined };
}

/** Reduce any thrown value to a safe message string — never the raw object. */
function safeErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return "unknown error";
}

function parseExpiryDays(raw: string): number | null | undefined {
  const days = Number(raw);
  if (!Number.isFinite(days) || days <= 0) return undefined;
  return Date.now() + days * 24 * 60 * 60 * 1000;
}

async function runCreate(
  args: readonly string[],
  io: CliIo,
  deps: CredentialCliDeps,
): Promise<number> {
  const allowed = ["agent", "agent-name", "label", "expires-in-days"] as const;
  const { flags, error } = parseFlags(args, allowed);
  if (error !== undefined) {
    io.err(`create: ${error}`);
    return 1;
  }

  const agentId = flags.get("agent");
  if (agentId === undefined || agentId.length === 0) {
    io.err("create requires --agent <id>");
    return 1;
  }

  const daysRaw = flags.get("expires-in-days");
  let expiresAt: number | null = null;
  if (daysRaw !== undefined) {
    const parsed = parseExpiryDays(daysRaw);
    if (parsed === undefined) {
      io.err("--expires-in-days must be a positive number");
      return 1;
    }
    expiresAt = parsed;
  }

  const agentName = flags.get("agent-name");
  const label = flags.get("label");

  const created = await deps.service.create({
    agentId,
    ...(agentName !== undefined ? { agentName } : {}),
    ...(label !== undefined ? { label } : {}),
    ...(expiresAt !== null ? { expiresAt } : {}),
  });

  // The plaintext key appears on exactly one line, exactly once.
  io.out(`Created credential for agent "${created.agent.id}".`);
  io.out(`  key id:  ${created.keyId}`);
  io.out(`  api key: ${created.apiKey}`);
  io.out("");
  io.out("Store this API key now. It is shown once and cannot be retrieved again.");
  return 0;
}

async function runRevoke(
  args: readonly string[],
  io: CliIo,
  deps: CredentialCliDeps,
): Promise<number> {
  const { flags, error } = parseFlags(args, ["key-id"]);
  if (error !== undefined) {
    io.err(`revoke: ${error}`);
    return 1;
  }

  const keyId = flags.get("key-id");
  if (keyId === undefined || keyId.length === 0) {
    io.err("revoke requires --key-id <id>");
    return 1;
  }

  const revoked = await deps.service.revoke(keyId);
  if (!revoked) {
    io.err(`No active credential with key id ${keyId}.`);
    return 1;
  }
  io.out(`Revoked credential ${keyId}.`);
  return 0;
}

async function runList(
  args: readonly string[],
  io: CliIo,
  deps: CredentialCliDeps,
): Promise<number> {
  const { flags, error } = parseFlags(args, ["agent"]);
  if (error !== undefined) {
    io.err(`list: ${error}`);
    return 1;
  }

  const agentId = flags.get("agent");
  if (agentId === undefined || agentId.length === 0) {
    io.err("list requires --agent <id>");
    return 1;
  }

  const credentials = await deps.service.listByAgent(agentId);
  if (credentials.length === 0) {
    io.out(`No credentials for agent "${agentId}".`);
    return 0;
  }

  io.out(`Credentials for agent "${agentId}":`);
  for (const credential of credentials) {
    const state =
      credential.revokedAt !== null ? "revoked" : credential.active ? "active" : "expired";
    const label = credential.label !== undefined ? `  (${credential.label})` : "";
    io.out(`  ${credential.keyId}  ${state}${label}`);
  }
  return 0;
}

/**
 * Run the credential CLI. Returns the process exit code. Pure with respect to
 * process state — the caller supplies IO and the service, so this is testable.
 */
export async function runCredentialCli(
  argv: readonly string[],
  io: CliIo,
  deps: CredentialCliDeps,
): Promise<number> {
  const command = argv[0];

  if (command === undefined || command === "--help" || command === "help") {
    io.out(USAGE);
    return 0;
  }

  if (argv.includes("--help")) {
    io.out(USAGE);
    return 0;
  }

  try {
    switch (command) {
      case "create":
        return await runCreate(argv.slice(1), io, deps);
      case "revoke":
        return await runRevoke(argv.slice(1), io, deps);
      case "list":
        return await runList(argv.slice(1), io, deps);
      default:
        io.err(`Unknown command "${command}".`);
        io.err(USAGE);
        return 1;
    }
  } catch (error) {
    // Message only — never the raw error object, and never credential material.
    io.err(`${command} failed: ${safeErrorMessage(error)}`);
    return 1;
  }
}

/* ------------------------------------------------------------------ */
/* CLI bootstrap — only runs when executed directly, never on import.  */
/* ------------------------------------------------------------------ */

const isCli =
  process.argv[1] != null && import.meta.url === new URL(`file://${process.argv[1]}`).href;

if (isCli) {
  const databaseUrl = process.env.DATABASE_URL;
  if (databaseUrl === undefined || databaseUrl.length === 0) {
    console.error("credential CLI requires DATABASE_URL to be set");
    process.exit(1);
  }

  const { createDbPool, disposeDbPool } = await import("../db/client.js");
  const { runMigrations } = await import("../db/migrate.js");
  const { buildPgRepositories } = await import("../repositories/pg.js");

  const pool = createDbPool(databaseUrl);
  try {
    await runMigrations(pool);
    const repositories = buildPgRepositories(pool);
    const hasher = new ScryptSecretHasher({ pepper: process.env.CREDENTIAL_PEPPER ?? "" });
    const service = new DefaultCredentialService(repositories, hasher);

    process.exitCode = await runCredentialCli(
      process.argv.slice(2),
      {
        out: (line) => console.log(line),
        err: (line) => console.error(line),
      },
      { service },
    );
  } catch (error) {
    console.error(
      `credential CLI failed: ${error instanceof Error ? error.message : "unknown error"}`,
    );
    process.exitCode = 1;
  } finally {
    await disposeDbPool(pool);
  }
}
