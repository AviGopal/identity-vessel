/**
 * The class rule (services/owner-kind.ts) and the unit-start backfill that stamps existing
 * api_key rows with it (db/migrations.ts migrateOnStart, after the migration files apply).
 *
 * MUST-FAIL on a tree without them: the module does not exist, and migration 005, which
 * declares api_key.owner_kind, is not shipped.
 * The database is a fake; every row is a synthetic fixture.
 */

import { test, expect, describe } from 'bun:test';
import { mkdtempSync, rmSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { deriveOwnerKind, ownerKindAtIssue, ADMIN_CREDENTIAL_NAMES, storedOrDerived, backfillOwnerKind, BACKFILL_SELECT, BACKFILL_UPDATE } from './owner-kind';
import { migrateOnStart, migrationFiles, MIGRATIONS_DIR, type RunSql } from '../db/migrations';

describe('deriveOwnerKind: the documented name patterns', () => {
  test("the seeder's vessel service key names are 'system'", () => {
    for (const n of ['substrate-default', 'local-tools-vessel', 'goal-host-vessel', 'goal-host-corpus-runner', 'concept-db']) {
      expect(deriveOwnerKind(n)).toBe('system');
    }
  });
  test("each admin credential name is 'unclassified', never 'operator'", () => {
    expect([...ADMIN_CREDENTIAL_NAMES]).toEqual(['substrate-admin', 'substrate-admin-backfill', 'substrate-admin-bootstrap']);
    for (const n of ['substrate-admin', 'substrate-admin-backfill', 'substrate-admin-bootstrap']) {
      expect(deriveOwnerKind(n)).toBe('unclassified');
      expect(ownerKindAtIssue(n, undefined)).toBe('unclassified');
    }
  });
  test("no name derives 'operator': it comes only from a declaration at issue", () => {
    for (const n of ['operator', 'substrate-operator', 'fixture-person', 'substrate-admin']) {
      expect(deriveOwnerKind(n)).not.toBe('operator');
    }
    expect(ownerKindAtIssue('substrate-admin', 'operator')).toBe('operator');
  });
  test("an untraceable row (free-form, absent, empty, near-miss or non-string name) is 'unclassified'", () => {
    for (const n of ['fixture-peer-node', 'Goal-Host-Vessel', 'goal-host-vessel ', 'substrate', '', undefined, null, 7]) {
      expect(deriveOwnerKind(n)).toBe('unclassified');
    }
  });
  test("an issuer may declare only 'operator' or 'peer'", () => {
    expect(ownerKindAtIssue('goal-host-vessel', undefined)).toBe('system');
    expect(ownerKindAtIssue('goal-host-vessel', 'operator')).toBe('operator');
    expect(ownerKindAtIssue('fixture-name', 'peer')).toBe('peer');
    expect(ownerKindAtIssue('fixture-name', 'system')).toBeNull();
    expect(ownerKindAtIssue('fixture-name', 'unclassified')).toBeNull();
  });
  test('a stored class is kept; a missing or unknown one is derived', () => {
    expect(storedOrDerived('operator', 'goal-host-vessel')).toBe('operator');
    expect(storedOrDerived(undefined, 'goal-host-vessel')).toBe('system');
    expect(storedOrDerived('bogus', 'fixture-name')).toBe('unclassified');
  });
});

describe('the backfill of existing rows', () => {
  const ROWS = [
    { id: 'api_key:fixture1', name: 'goal-host-vessel' },
    { id: 'api_key:fixture2', name: 'substrate-admin' },
    { id: 'api_key:fixture3', name: 'fixture-free-form' },
    { id: 'api_key:fixture4' },
  ];

  test('each unstamped row is stamped by its name, one conditional UPDATE per row; a refused row is counted and skipped', async () => {
    const updates: Array<Record<string, unknown>> = [];
    const run: RunSql = async (sql, params) => {
      if (sql === BACKFILL_SELECT) return [ROWS];
      if (sql === BACKFILL_UPDATE) {
        if (params?.id === 'api_key:fixture3') throw new Error('fixture: row refused by the schema');
        updates.push(params ?? {});
        return [[]];
      }
      throw new Error(`unexpected SQL: ${sql}`);
    };
    const r = await backfillOwnerKind(run);
    expect(updates).toEqual([
      { id: 'api_key:fixture1', owner_kind: 'system' },
      { id: 'api_key:fixture2', owner_kind: 'unclassified' },
      { id: 'api_key:fixture4', owner_kind: 'unclassified' },
    ]);
    expect(r).toEqual({ stamped: { system: 1, operator: 0, peer: 0, unclassified: 2 }, failed: 1 });
    expect(BACKFILL_SELECT).toContain('WHERE owner_kind = NONE');
    expect(BACKFILL_UPDATE).toContain('WHERE owner_kind = NONE');
    expect(BACKFILL_SELECT).not.toContain('key_hash');
  });

  test('migration 005 declares owner_kind with the four values, and ships after 004', async () => {
    const files = await migrationFiles();
    expect(files).toContain('005-api-key-owner-kind.surql');
    expect(files.indexOf('005-api-key-owner-kind.surql')).toBeGreaterThan(files.indexOf('004-tenant-isolation-permissions.surql'));
    const text = readFileSync(join(MIGRATIONS_DIR, '005-api-key-owner-kind.surql'), 'utf8');
    expect(text).toMatch(/DEFINE FIELD OVERWRITE owner_kind ON api_key TYPE option<string>/);
    expect(text).toContain('["system", "operator", "peer", "unclassified"]');
  });

  test('the unit start runs the backfill after the files, and a backfill that fails does not fail the start', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'owner-kind-start-'));
    try {
      for (const failing of [false, true]) {
        const seen: string[] = [];
        const run: RunSql = async (sql) => {
          if (/DEFINE TABLE IF NOT EXISTS init_migrations/.test(sql)) { seen.push('ledger'); return [null]; }
          if (/^SELECT VALUE filename FROM init_migrations/.test(sql)) return [[]];
          if (sql === BACKFILL_SELECT) {
            seen.push('backfill');
            if (failing) throw new Error('fixture: datastore refused the read');
            return [[{ id: 'api_key:fixture1', name: 'concept-db' }]];
          }
          if (sql === BACKFILL_UPDATE) { seen.push('stamp'); return [[]]; }
          throw new Error(`unexpected SQL: ${sql}`);
        };
        const report = await migrateOnStart(async () => run, { dir });
        expect(report).toEqual({ applied: [], skipped: [] });
        expect(seen).toEqual(failing ? ['ledger', 'backfill'] : ['ledger', 'backfill', 'stamp']);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
