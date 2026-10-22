/**
 * identity applies its own migrations on every unit start, records each in the
 * init_migrations ledger, skips what the ledger already holds, and fails the start on a
 * migration that does not apply, recording it. No environment variable switches any of it.
 *
 * The database is a fake that keeps the ledger and the failure rows the runner writes,
 * so each case reads back what the runner recorded rather than what it logged.
 */

import { test, expect, describe, beforeEach, afterEach } from 'bun:test';
import { mkdtempSync, writeFileSync, rmSync, readFileSync, copyFileSync, readdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { applyMigrations, LEDGER_PREFIX, MIGRATIONS_DIR, type RunSql } from './migrations';

interface Stored {
  ledger: Set<string>;
  failures: Map<string, { failure_count: number; last_error: string }>;
}

interface FakeDb extends Stored {
  run: RunSql;
  executed: string[]; // migration files whose body was run on this start
}

/** A fake database for one unit start; pass the previous start's `stored` to model a restart. */
function fakeDb(dir: string, stored: Stored = { ledger: new Set(), failures: new Map() }): FakeDb {
  const { ledger, failures } = stored;
  const executed: string[] = [];
  const run: RunSql = async (sql, params) => {
    if (/DEFINE TABLE IF NOT EXISTS init_migrations/.test(sql)) return [null, null, null, null];
    if (/^SELECT VALUE filename FROM init_migrations/.test(sql)) {
      const keys = (params?.keys as string[]) ?? [];
      return [keys.filter((k) => ledger.has(k))];
    }
    if (/INSERT IGNORE INTO init_migrations/.test(sql)) {
      const f = params?.filename as string;
      ledger.add(f);
      failures.delete(f);
      return [[{ filename: f }], []];
    }
    if (/init_migration_failures/.test(sql) && /failure_count/.test(sql)) {
      const f = params?.filename as string;
      const prev = failures.get(f);
      failures.set(f, { failure_count: (prev?.failure_count ?? 0) + 1, last_error: String(params?.error) });
      return [null];
    }
    const file = readdirSync(dir).find((f) => readFileSync(join(dir, f), 'utf8') === sql);
    if (!file) throw new Error(`fake db: unexpected SQL: ${sql.slice(0, 80)}`);
    executed.push(file);
    if (sql.includes('BROKEN')) throw new Error(`Parse error in ${file}`);
    return [null];
  };
  return { run, ledger, failures, executed };
}

let dir: string;
let savedEnv: string | undefined;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'id-migrations-'));
  savedEnv = process.env.SCHEMA_AUTOAPPLY;
  delete process.env.SCHEMA_AUTOAPPLY;
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  if (savedEnv === undefined) delete process.env.SCHEMA_AUTOAPPLY;
  else process.env.SCHEMA_AUTOAPPLY = savedEnv;
});

function copyShipped(): string[] {
  const files = readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith('.surql')).sort();
  for (const f of files) copyFileSync(join(MIGRATIONS_DIR, f), join(dir, f));
  return files;
}

describe('unit start applies identity migrations', () => {
  test('with no environment variable set, every shipped migration applies in filename order and is recorded', async () => {
    const files = copyShipped();
    expect(files.slice(0, 4)).toEqual([
      '001-api-keys.surql',
      '002-users-password-hash.surql',
      '003-key-sessions.surql',
      '004-tenant-isolation-permissions.surql',
    ]);
    const db = fakeDb(dir);

    const report = await applyMigrations(db.run, dir);

    expect(report.applied).toEqual(files);
    expect(db.executed).toEqual(files);
    expect([...db.ledger].sort()).toEqual(files.map((f) => LEDGER_PREFIX + f));
  });

  test('the startup path runs the runner unconditionally and reads no switch for it', () => {
    const index = readFileSync(join(import.meta.dir, '../index.ts'), 'utf8');
    expect(index).not.toContain('SCHEMA_AUTOAPPLY');
    expect(index).toMatch(/await applyMigrations\(/);
  });

  test('a migration the ledger already records is not run again', async () => {
    const files = copyShipped();
    const db = fakeDb(dir);
    db.ledger.add(LEDGER_PREFIX + files[0]);
    db.ledger.add(LEDGER_PREFIX + files[1]);

    const report = await applyMigrations(db.run, dir);

    expect(report.skipped).toEqual(files.slice(0, 2));
    expect(db.executed).toEqual(files.slice(2));

    const again = await applyMigrations(db.run, dir);
    expect(again.applied).toEqual([]);
    expect(db.executed).toEqual(files.slice(2));
  });

  test('a bare-named ledger row from another vessel does not mark an identity file applied', async () => {
    const files = copyShipped();
    const db = fakeDb(dir);
    db.ledger.add(files[0]);

    const report = await applyMigrations(db.run, dir);

    expect(report.applied).toContain(files[0]);
  });
});

describe('a migration that fails', () => {
  beforeEach(() => {
    writeFileSync(join(dir, '001-ok.surql'), 'DEFINE FIELD OVERWRITE a ON t TYPE string;');
    writeFileSync(join(dir, '002-broken.surql'), 'DEFINE FIELD BROKEN ON t TYPE;');
    writeFileSync(join(dir, '003-after.surql'), 'DEFINE FIELD OVERWRITE c ON t TYPE string;');
  });

  test('fails the start loudly, is recorded as failed, and nothing after it runs or is recorded', async () => {
    const db = fakeDb(dir);

    await expect(applyMigrations(db.run, dir)).rejects.toThrow(/migration 002-broken\.surql failed/);

    expect(db.executed).toEqual(['001-ok.surql', '002-broken.surql']);
    expect([...db.ledger]).toEqual([LEDGER_PREFIX + '001-ok.surql']);
    expect(db.failures.get(LEDGER_PREFIX + '002-broken.surql')?.failure_count).toBe(1);
    expect(db.failures.get(LEDGER_PREFIX + '002-broken.surql')?.last_error).toMatch(/Parse error/);
  });

  test('fails again on the next start, counted; once fixed it applies and its failure row is cleared', async () => {
    const first = fakeDb(dir);
    await expect(applyMigrations(first.run, dir)).rejects.toThrow();

    const second = fakeDb(dir, first);
    await expect(applyMigrations(second.run, dir)).rejects.toThrow(/002-broken/);
    expect(second.executed).toEqual(['002-broken.surql']);
    expect(second.failures.get(LEDGER_PREFIX + '002-broken.surql')?.failure_count).toBe(2);

    writeFileSync(join(dir, '002-broken.surql'), 'DEFINE FIELD OVERWRITE b ON t TYPE string;');
    const third = fakeDb(dir, second);
    const report = await applyMigrations(third.run, dir);
    expect(report.applied).toEqual(['002-broken.surql', '003-after.surql']);
    expect(third.failures.has(LEDGER_PREFIX + '002-broken.surql')).toBe(false);
    expect(third.ledger.has(LEDGER_PREFIX + '003-after.surql')).toBe(true);
  });
});
