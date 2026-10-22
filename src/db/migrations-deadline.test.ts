/**
 * The unit-start schema step is bounded: a datastore that accepts the connection and then
 * never answers must fail the start (so identity exits non-zero) within the bound, and a
 * migration that never returns is recorded as failed when the ledger still answers.
 * Without the bound the start hangs with no listener and no exit.
 */

import { test, expect, describe, beforeEach, afterEach } from 'bun:test';
import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import * as migrations from './migrations';
import type { RunSql } from './migrations';

const never = () => new Promise<never>(() => {});

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'id-migrations-deadline-'));
  writeFileSync(join(dir, '001-ok.surql'), 'DEFINE FIELD OVERWRITE a ON t TYPE string;');
  writeFileSync(join(dir, '002-stalls.surql'), 'DEFINE FIELD OVERWRITE stalls ON t TYPE string;');
  writeFileSync(join(dir, '003-after.surql'), 'DEFINE FIELD OVERWRITE c ON t TYPE string;');
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

/** A ledger that answers, and a datastore that never answers whatever `stall` matches. */
function stallingDb(stall: (sql: string) => boolean) {
  const ledger = new Set<string>();
  const failures = new Map<string, string>();
  const ran: string[] = [];
  const run: RunSql = async (sql, params) => {
    if (stall(sql)) return never();
    if (/^SELECT VALUE filename FROM init_migrations/.test(sql)) return [[]];
    if (/INSERT IGNORE INTO init_migrations/.test(sql)) {
      ledger.add(params?.filename as string);
      return [[], []];
    }
    if (/init_migration_failures/.test(sql) && /failure_count/.test(sql)) {
      failures.set(params?.filename as string, String(params?.error));
      return [null];
    }
    ran.push(sql);
    return [null];
  };
  return { run, ledger, failures, ran };
}

async function elapsed<T>(work: Promise<T>): Promise<{ ms: number; error: string }> {
  const t0 = Date.now();
  const error = await work.then(() => 'resolved', (e: Error) => e.message);
  return { ms: Date.now() - t0, error };
}

describe('the unit-start schema step is bounded', () => {
  test('a datastore that never completes the connection fails the start within the bound', async () => {
    expect(typeof migrations.migrateOnStart).toBe('function');
    const r = await elapsed(migrations.migrateOnStart(() => never(), { dir, deadlineMs: 200 }));
    expect(r.error).toMatch(/connecting to the datastore did not finish within 200 ms/);
    expect(r.ms).toBeLessThan(1500);
  }, 3000);

  test('a migration that never returns fails the start within the bound, is recorded, and nothing after it runs', async () => {
    const db = stallingDb((sql) => sql.includes('stalls'));
    const r = await elapsed(migrations.applyMigrations(db.run, dir, { deadlineMs: 300 }));
    expect(r.error).toMatch(/migration 002-stalls\.surql failed: migration 002-stalls\.surql did not finish within/);
    expect(r.ms).toBeLessThan(1500);
    expect(db.failures.get(migrations.LEDGER_PREFIX + '002-stalls.surql')).toMatch(/did not finish within/);
    expect([...db.ledger]).toEqual([migrations.LEDGER_PREFIX + '001-ok.surql']);
    expect(db.ran.some((s) => s.includes(' c ON t'))).toBe(false);
  }, 3000);

  test('a ledger that never answers fails the start within the bound', async () => {
    const db = stallingDb((sql) => /^SELECT VALUE filename FROM init_migrations/.test(sql));
    const r = await elapsed(migrations.migrateOnStart(async () => db.run, { dir, deadlineMs: 200 }));
    expect(r.error).toMatch(/reading the migration ledger did not finish within/);
    expect(r.ms).toBeLessThan(1500);
    expect(db.ran.filter((s) => s.includes(' ON t '))).toEqual([]);
  }, 3000);

  test('a failure record that never answers does not hold the start open past its own bound', async () => {
    const db = stallingDb((sql) => sql.includes('stalls') || /init_migration_failures/.test(sql) && /failure_count/.test(sql));
    const r = await elapsed(migrations.applyMigrations(db.run, dir, { deadlineMs: 200 }));
    expect(r.error).toMatch(/migration 002-stalls\.surql failed/);
    expect(r.ms).toBeLessThan(7000);
  }, 9000);

  test('control: a step that answers within the bound applies and records every file', async () => {
    const db = stallingDb(() => false);
    const report = await migrations.migrateOnStart(async () => db.run, { dir, deadlineMs: 2000 });
    expect(report.applied).toEqual(['001-ok.surql', '002-stalls.surql', '003-after.surql']);
    expect(db.ledger.size).toBe(3);
  }, 3000);
});
