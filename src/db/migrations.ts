/**
 * Schema migrations for identity-vessel-owned tables, applied on every unit start.
 *
 * The same mechanism as activity-api's init-database runner: every `.surql` file in
 * sql/migrations is applied in sorted filename order, and each applied file is recorded
 * in the fleet's `init_migrations` ledger so a later start skips it. Nothing switches it
 * off: the schema these files declare (api_key, key_session and their PERMISSIONS on
 * $token.org_id) is what tenant isolation rests on, so a start that cannot apply it must
 * not serve as if it had.
 *
 * Ledger rows are written as `identity-vessel/<file>`. The ledger is shared with
 * activity-api, which matches its own files by bare filename, so the vessel prefix keeps
 * the two owners' files from ever reading as each other's.
 *
 * A file that fails is recorded in `init_migration_failures` (the table activity-api's
 * runner uses, with a `last_error`) and the start fails: applyMigrations throws, the files
 * after it are not attempted, and nothing is recorded as applied that did not apply. A
 * later successful apply clears the failure row.
 *
 * The whole step is bounded (START_DEADLINE_MS): a datastore that accepts the connection
 * and then never answers fails the start like any other failure, instead of leaving
 * identity with no listener and no exit.
 */

import { readdir } from 'fs/promises';
import { join } from 'path';

/** Runs SurrealQL and resolves with every statement's result; rejects when any statement fails. */
export type RunSql = (sql: string, params?: Record<string, unknown>) => Promise<unknown[]>;

export const MIGRATIONS_DIR = join(import.meta.dir, '../../sql/migrations');
export const LEDGER_PREFIX = 'identity-vessel/';

// The ledger statements are verbatim from activity-api's ensureMigrationsTable, so whichever
// vessel starts first defines the ledger identically. activity-api creates the failure table
// implicitly on its first INSERT; it is defined here as that implicit table is, because
// SurrealDB 3.x refuses a DELETE or SELECT on a table that does not exist yet.
const ENSURE_LEDGER = `
    DEFINE TABLE IF NOT EXISTS init_migrations SCHEMAFULL
      PERMISSIONS FOR select, create FULL;
    DEFINE FIELD IF NOT EXISTS filename ON init_migrations TYPE string;
    DEFINE FIELD IF NOT EXISTS applied_at ON init_migrations TYPE datetime DEFAULT time::now();
    DEFINE INDEX IF NOT EXISTS idx_init_migrations_filename ON init_migrations FIELDS filename UNIQUE;
    DEFINE TABLE IF NOT EXISTS init_migration_failures SCHEMALESS;
  `;

const RECORD_APPLIED = `
    INSERT IGNORE INTO init_migrations (filename) VALUES ($filename);
    DELETE init_migration_failures WHERE filename = $filename;
  `;

const RECORD_FAILED = `
    IF (SELECT VALUE id FROM init_migration_failures WHERE filename = $filename LIMIT 1)[0] != NONE {
      UPDATE init_migration_failures SET failure_count += 1, last_error = $error, updated_at = time::now()
        WHERE filename = $filename;
    } ELSE {
      CREATE init_migration_failures SET filename = $filename, failure_count = 1, last_error = $error,
        updated_at = time::now();
    };
  `;

// BOOTSTRAP TIER: the bound on a unit start's schema step (connecting, then every pending
// migration). It is a literal, not a shaped setting, because identity's shaped settings live
// in the datastore this step is waiting on, so none can be read before it. 120 s is the
// identity seeder's wait for /health on boot: a start slower than that misses the seed
// anyway. A step that runs out fails the start; the next start re-runs whatever was not
// recorded, which DEFINE ... OVERWRITE makes safe.
export const START_DEADLINE_MS = 120_000;
// Recording a failure gets its own bound, because the step's may already be spent.
const RECORD_FAILURE_DEADLINE_MS = 5_000;

export class DeadlineExceeded extends Error {}

function within<T>(work: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expired = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new DeadlineExceeded(`${what} did not finish within ${ms} ms`)), Math.max(0, ms));
  });
  return Promise.race([work, expired]).finally(() => clearTimeout(timer));
}

export interface MigrationOptions {
  /** Bound on the whole step, in ms (default START_DEADLINE_MS). */
  deadlineMs?: number;
}

export interface MigrationReport {
  applied: string[];
  skipped: string[];
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** The migration files, in the order they apply. */
export async function migrationFiles(dir: string = MIGRATIONS_DIR): Promise<string[]> {
  return (await readdir(dir)).filter((f) => f.endsWith('.surql')).sort();
}

/**
 * Apply every migration not yet recorded in the ledger. Resolves with what was applied
 * and what was already recorded; throws on the first file that fails, after recording it,
 * and on any statement still unanswered when the step's deadline runs out.
 */
export async function applyMigrations(
  run: RunSql,
  dir: string = MIGRATIONS_DIR,
  opts: MigrationOptions & { until?: number } = {},
): Promise<MigrationReport> {
  const until = opts.until ?? Date.now() + (opts.deadlineMs ?? START_DEADLINE_MS);
  const step = (what: string, sql: string, params?: Record<string, unknown>) =>
    within(run(sql, params), until - Date.now(), what);

  const files = await migrationFiles(dir);
  await step('ensuring the migration ledger', ENSURE_LEDGER);

  const keys = files.map((f) => LEDGER_PREFIX + f);
  const [rows] = await step('reading the migration ledger', 'SELECT VALUE filename FROM init_migrations WHERE filename IN $keys;', { keys });
  const recorded = new Set<string>(Array.isArray(rows) ? (rows as string[]) : []);

  const report: MigrationReport = { applied: [], skipped: [] };
  for (const file of files) {
    const filename = LEDGER_PREFIX + file;
    if (recorded.has(filename)) {
      report.skipped.push(file);
      continue;
    }

    try {
      await step(`migration ${file}`, await Bun.file(join(dir, file)).text());
    } catch (err) {
      const error = message(err);
      console.error('[Schema] migration failed', { file, err: error });
      try {
        await within(run(RECORD_FAILED, { filename, error }), RECORD_FAILURE_DEADLINE_MS, 'recording the failure');
      } catch (recordErr) {
        console.error('[Schema] could not record the failure', { file, err: message(recordErr) });
      }
      throw new Error(`migration ${file} failed: ${error}`);
    }

    await step(`recording ${file}`, RECORD_APPLIED, { filename });
    console.log('[Schema] applied', { file });
    report.applied.push(file);
  }
  return report;
}

/**
 * The unit-start schema step: connect, then apply. One deadline covers both, so a
 * datastore that never completes the connection fails the start within the bound too.
 */
export async function migrateOnStart(
  connect: () => Promise<RunSql>,
  opts: MigrationOptions & { dir?: string } = {},
): Promise<MigrationReport> {
  const deadlineMs = opts.deadlineMs ?? START_DEADLINE_MS;
  const until = Date.now() + deadlineMs;
  const run = await within(connect(), deadlineMs, 'connecting to the datastore');
  return applyMigrations(run, opts.dir, { until });
}
