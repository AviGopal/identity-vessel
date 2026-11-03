/**
 * A key is stamped with its class (owner_kind) at issue, by the one rule the backfill and the
 * apiKeyClass resolver use (services/owner-kind.ts): a vessel service key the seeder names is
 * 'system', a key declared 'operator' at issue 'operator', any other name (the admin
 * credential's included) 'unclassified'. An issuer may declare 'operator' and nothing else.
 *
 * MUST-FAIL on a tree without the stamp: the CREATE carries no owner_kind.
 * The database is a stub that captures the CREATE; no key leaves this process.
 */

import { test, expect, describe, afterEach, mock } from 'bun:test';

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
    throw new Error('SurrealDB stubbed in issue-key owner_kind test');
  },
}));

import { mintApiKey, setQueryFn } from './issue-key';

const ORG = 'organizations:fixtureorg';
const USER = 'users:fixture';

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

describe('owner_kind is stamped at issue', () => {
  afterEach(() => setQueryFn(null));

  test("a newly issued vessel service key (the seeder's name for it) is stamped 'system'", async () => {
    for (const name of ['goal-host-vessel', 'substrate-default', 'concept-db']) {
      const { result, sql, params } = await mint({ name });
      expect(result.ok).toBe(true);
      expect(sql).toContain('owner_kind = $owner_kind');
      expect(params?.owner_kind).toBe('system');
    }
  });

  test("an operator-session key (declared 'operator') is stamped 'operator', over a system name too", async () => {
    const a = await mint({ name: 'fixture-session', owner_kind: 'operator' });
    expect(a.result.ok).toBe(true);
    expect(a.params?.owner_kind).toBe('operator');
    const b = await mint({ name: 'goal-host-vessel', owner_kind: 'operator' });
    expect(b.params?.owner_kind).toBe('operator');
  });

  test("each admin credential name is stamped 'unclassified' unless the issuer declares 'operator'", async () => {
    for (const name of ['substrate-admin', 'substrate-admin-backfill', 'substrate-admin-bootstrap']) {
      const { params } = await mint({ name, scopes: ['read', 'write', 'admin'] });
      expect(params?.owner_kind).toBe('unclassified');
    }
    const declared = await mint({ name: 'substrate-admin', scopes: ['read', 'write', 'admin'], owner_kind: 'operator' });
    expect(declared.params?.owner_kind).toBe('operator');
  });

  test("an untraceable name, or none, is stamped 'unclassified'", async () => {
    expect((await mint({ name: 'fixture-peer-node' })).params?.owner_kind).toBe('unclassified');
    expect((await mint({})).params?.owner_kind).toBe('unclassified');
  });

  test("declaring any class but 'operator' is refused, and nothing is written", async () => {
    for (const owner_kind of ['system', 'peer', 'unclassified', 'SYSTEM', 7]) {
      const { result, sql } = await mint({ name: 'goal-host-vessel', owner_kind });
      expect(result.ok).toBe(false);
      expect(result.status).toBe(400);
      expect(result.code).toBe('INVALID_INPUT');
      expect(sql).toBeNull();
    }
  });
});
