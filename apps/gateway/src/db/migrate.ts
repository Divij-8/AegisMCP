/**
 * Forward-only SQL migration runner.
 *
 * - Migrations live in src/db/migrations as NNNN_name.sql files.
 * - Applied migrations are tracked in schema_migrations.
 * - Each migration runs inside a transaction: a failure leaves no
 *   half-applied state (fail-closed, mirroring policy validation).
 * - No down migrations: rollback is a new forward migration.
 *
 * CLI usage: node dist/db/migrate.js (used by `pnpm --filter @aegis/gateway db:migrate`).
 */

import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Pool } from "pg";

const MIGRATIONS_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "migrations");

const MIGRATION_FILE_PATTERN = /^(\d{4}_[a-z0-9_]+)\.sql$/;

export interface MigrationResult {
  readonly applied: readonly string[];
  readonly skipped: readonly string[];
}

interface MigrationFile {
  readonly id: string;
  readonly sql: string;
}

async function loadMigrationFiles(): Promise<readonly MigrationFile[]> {
  const entries = await readdir(MIGRATIONS_DIR);
  const files: MigrationFile[] = [];

  for (const entry of entries) {
    if (!MIGRATION_FILE_PATTERN.test(entry)) continue;
    const id = entry.replace(/\.sql$/, "");
    const sql = await readFile(path.join(MIGRATIONS_DIR, entry), "utf-8");
    files.push({ id, sql });
  }

  files.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  // Enforce a gapless 0001, 0002, ... prefix ordering.
  files.forEach((file, index) => {
    const expected = String(index + 1).padStart(4, "0");
    if (!file.id.startsWith(expected)) {
      throw new Error(
        `Migration files must be numbered sequentially: expected ${expected}_*, found ${file.id}`,
      );
    }
  });

  return files;
}

async function ensureMigrationsTable(client: { query: Pool["query"] }): Promise<void> {
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      id         TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
}

/**
 * Apply all pending migrations. Safe to call repeatedly — already-applied
 * migrations are skipped, so this is idempotent.
 *
 * Concurrency: takes a session-scoped advisory lock so concurrent runners
 * (gateway boot racing CI migrate, or two gateway instances) serialize
 * instead of racing CREATE TABLE / INSERT.
 */
const MIGRATION_LOCK_KEY = 0x61656769; // "aegi"

export async function runMigrations(pool: Pool): Promise<MigrationResult> {
  const client = await pool.connect();
  try {
    await client.query("SELECT pg_advisory_lock($1)", [MIGRATION_LOCK_KEY]);
    await ensureMigrationsTable(client);

    const files = await loadMigrationFiles();
    const { rows } = await client.query<{ id: string }>("SELECT id FROM schema_migrations");
    const appliedIds = new Set(rows.map((row) => row.id));

    const applied: string[] = [];
    const skipped: string[] = [];

    for (const file of files) {
      if (appliedIds.has(file.id)) {
        skipped.push(file.id);
        continue;
      }

      try {
        await client.query("BEGIN");
        await client.query("INSERT INTO schema_migrations (id) VALUES ($1)", [file.id]);
        await client.query(file.sql);
        await client.query("COMMIT");
        applied.push(file.id);
      } catch (err) {
        await client.query("ROLLBACK");
        throw new Error(
          `Migration ${file.id} failed: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }

    return { applied, skipped };
  } finally {
    try {
      await client.query("SELECT pg_advisory_unlock($1)", [MIGRATION_LOCK_KEY]);
    } finally {
      client.release();
    }
  }
}

const isCli =
  process.argv[1] != null && import.meta.url === new URL(`file://${process.argv[1]}`).href;

if (isCli) {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    console.error("db:migrate requires DATABASE_URL to be set");
    process.exit(1);
  }

  const { createDbPool, disposeDbPool } = await import("./client.js");
  const pool = createDbPool(databaseUrl);
  try {
    const result = await runMigrations(pool);
    for (const id of result.applied) console.log(`applied  ${id}`);
    for (const id of result.skipped) console.log(`skipped  ${id}`);
  } catch (err) {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  } finally {
    await disposeDbPool(pool);
  }
}
