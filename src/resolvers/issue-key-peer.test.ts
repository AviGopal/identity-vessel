/**
 * A key may be declared 'peer' at issue, with the joining node's name as owner_node: the row
 * is stamped with both, and apiKeyClass serves the key as owner_kind 'peer' with that node.
 * 'peer' is never derived from a name, a peer declaration with no valid node name is refused,
 * and owner_node is accepted only together with 'peer'.
 *
 * MUST-FAIL on a tree that admits only 'operator': the peer issue below is refused with 400,
 * so the stamp and the served entry are red by assertion.
 * The database is a stub that captures the CREATE; every name and id is a synthetic fixture.
 */

import { test, expect, describe, afterEach, mock } from 'bun:test';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

mock.module('../db/redis', () => ({
  redis: {},
  isKeyRevoked: async () => false,
  revokeKey: async () => {},
  unrevokeKey: async () => {},
  getRateLimitKey: (endpoint: string, ip: string) => `ratelimit:${endpoint}:${ip}`,
  checkRateLimit: async () => ({ allowed: true, retryAfterSeconds: 0 }),
}));

mock.module('../db/surrealdb', () => ({
  query: async () => [],
  getSurrealDB: async () => {
    throw new Error('SurrealDB stubbed in issue-key peer test');
  },
}));

import { mintApiKey, setQueryFn } from './issue-key';
import { entryFromRow, deriveOwnerKind } from './key-class';

const ORG = 'organizations:fixtureorg';
const USER = 'users:fixture';
const MIGRATIONS = join(import.meta.dir, '../../sql/migrations');

async function mint(body: Record<string, unknown>): Promise<{ result: any; sql: string | null; params: Record<string, any> | null }> {
  let sql: string | null = null;
  let params: Record<string, any> | null = null;
  setQueryFn(async (s, p) => {
    sql = s;
    params = p ?? null;
    return [];
  });
  const result = await mintApiKey({ org_id: ORG, user_id: USER, ...body });
  return { result, sql, params };
}

/** The row the captured CREATE writes, as apiKeyClass reads it back. */
function storedRow(params: Record<string, any>): Record<string, unknown> {
  const { key_id, name, scopes, owner_kind, owner_node } = params;
  return { key_id, name, scopes, owner_kind, owner_node };
}

describe("a key declared 'peer' at issue, with its node", () => {
  afterEach(() => setQueryFn(null));

  test("[MUST-FAIL] issuing with owner_kind 'peer' and a node name stores both, and apiKeyClass serves them", async () => {
    const { result, sql, params } = await mint({ name: 'fixture-join-key', owner_kind: 'peer', owner_node: 'node-a' });
    expect(result.ok).toBe(true);
    expect(sql).toContain('owner_kind = $owner_kind');
    expect(sql).toContain('owner_node = $owner_node');
    expect(params?.owner_kind).toBe('peer');
    expect(params?.owner_node).toBe('node-a');
    const entry = entryFromRow(storedRow(params!), 'node-b');
    expect(entry).toEqual({ key_id_mask12: String(params!.key_id).slice(0, 12), owner_kind: 'peer', owner_node: 'node-a', is_admin: false });
  });

  test("a key NAMED like a peer node, with no declaration, still reads 'unclassified' and carries no node", async () => {
    for (const name of ['node-a', 'fixture-peer-node', 'peer']) {
      expect(deriveOwnerKind(name)).toBe('unclassified');
      const { result, sql, params } = await mint({ name });
      expect(result.ok).toBe(true);
      expect(params?.owner_kind).toBe('unclassified');
      expect(sql).not.toContain('owner_node');
      expect(params).not.toHaveProperty('owner_node');
      expect(entryFromRow(storedRow(params!), 'node-b')?.owner_node).toBeNull();
    }
  });

  test("owner_kind 'system', or any other value, declared at issue is refused with 400 and nothing is written", async () => {
    for (const owner_kind of ['system', 'unclassified', 'SYSTEM', 'Peer', '', 7, true]) {
      const { result, sql } = await mint({ name: 'goal-host-vessel', owner_kind, owner_node: 'node-a' });
      expect(result.ok).toBe(false);
      expect(result.status).toBe(400);
      expect(result.code).toBe('INVALID_INPUT');
      expect(result.message).toContain("'peer'");
      expect(sql).toBeNull();
    }
  });

  test("owner_kind 'peer' declared WITHOUT owner_node (absent, empty or non-string) is refused with 400: a peer key is never anonymous", async () => {
    for (const extra of [{}, { owner_node: null }, { owner_node: '' }, { owner_node: 7 }, { owner_node: ['node-a'] }, { owner_node: 'node a' }, { owner_node: '-node' }, { owner_node: 'n'.repeat(64) }]) {
      const { result, sql } = await mint({ name: 'fixture-join-key', owner_kind: 'peer', ...extra });
      expect(result.ok).toBe(false);
      expect(result.status).toBe(400);
      expect(result.code).toBe('INVALID_INPUT');
      expect(result.message).toContain('owner_node');
      expect(sql).toBeNull();
    }
  });

  test("owner_node is accepted only together with owner_kind 'peer'", async () => {
    for (const owner_kind of [undefined, 'operator']) {
      const { result, sql } = await mint({ name: 'fixture-session', owner_kind, owner_node: 'node-a' });
      expect(result.ok).toBe(false);
      expect(result.status).toBe(400);
      expect(result.message).toContain('owner_node');
      expect(sql).toBeNull();
    }
  });

  test('a stored peer row with no node is served with owner_node null', () => {
    expect(entryFromRow({ key_id: 'key_FIXTUREpeer0000F', owner_kind: 'peer', name: 'fixture-join-key' }, 'node-b'))
      .toEqual({ key_id_mask12: 'key_FIXTUREp', owner_kind: 'peer', owner_node: null, is_admin: false });
  });

  test('migration 006 declares api_key.owner_node, ships after 005, and stamps no existing row', () => {
    const file = join(MIGRATIONS, '006-api-key-owner-node.surql');
    expect(existsSync(file)).toBe(true);
    const text = readFileSync(file, 'utf8').replace(/--[^\n]*/g, '');
    expect(text).toMatch(/DEFINE FIELD OVERWRITE owner_node ON api_key TYPE option<string>/);
    expect(text).not.toMatch(/\b(UPDATE|CREATE|INSERT|DELETE)\b/i);
  });
});
