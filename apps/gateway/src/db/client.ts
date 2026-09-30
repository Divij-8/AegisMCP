/**
 * PostgreSQL connection management.
 *
 * The rest of the codebase never touches `pg` directly — only repositories
 * and the migration runner receive a Pool from here.
 */

import { Pool } from "pg";

export function createDbPool(databaseUrl: string): Pool {
  return new Pool({
    connectionString: databaseUrl,
    // Bounded pool: audit flushing is the main writer and is batched.
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
  });
}

export async function disposeDbPool(pool: Pool): Promise<void> {
  await pool.end();
}
