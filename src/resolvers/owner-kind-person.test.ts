/**
 * Which key is a person's is marked by an admin (apiKey_write owner_kind), never derived or declared at issue, and the
 * auth answer says it (ownerKind), so a reader takes a key's rows as a person's only for a key so marked.
 * Rows have the live shape: keys are minted through the real issue path (issue-key.ts), and the database stub permits
 * every write its WHERE matches, so every refusal comes from the resolver's own code.
 */
import { test, expect, describe, beforeEach, afterEach, mock } from 'bun:test';

mock.module('../db/redis', () => ({
  redis: {},
  isKeyRevoked: async () => false,
  revokeKey: async () => {},
  unrevokeKey: async () => {},
  getRateLimitKey: (endpoint: string, ip: string) => `ratelimit:${endpoint}:${ip}`,
  checkRateLimit: async () => ({ allowed: true, retryAfterSeconds: 0 }),
}));
mock.module('../db/surrealdb', () => ({
  query: async () => { throw new Error('SurrealDB query stubbed'); },
  getSurrealDB: async () => { throw new Error('SurrealDB stubbed'); },
}));

import { grantKeyScopes, setQueryFn } from './grant-scope';
import { mintApiKey, setQueryFn as setIssueQueryFn } from './issue-key';
import { setQueryFn as setValidationQueryFn, validateKey } from '../services/validation';
import { deriveOwnerKind, ownerKindAtIssue, OWNER_KINDS } from '../services/owner-kind';

const ORG = 'organizations:alpha';
let store: Record<string, any>[] = [];
let updates: Array<{ sql: string; params: Record<string, any> }> = [];

async function mint(scopes: string[], name: string): Promise<{ key: string; keyId: string }> {
  let created: Record<string, any> | null = null;
  setIssueQueryFn(async (_sql, params) => { created = { ...(params ?? {}) }; return []; });
  const r = await mintApiKey({ org_id: ORG, user_id: 'users:sys', scopes, name });
  setIssueQueryFn(null);
  if (!r.ok || !created) throw new Error('mint failed');
  store.push({ ...(created as Record<string, any>), is_active: true });
  return { key: r.key, keyId: r.key_id };
}
const rowOf = (keyId: string) => store.find((r) => r.key_id === keyId)!;

beforeEach(() => {
  store = [];
  updates = [];
  setValidationQueryFn(async (_sql, params) => {
    const r = store.find((x) => x.key_id === params?.key_id);
    return r ? [{ scopes: [...r.scopes], name: r.name, owner_kind: r.owner_kind }] : [];
  });
  setQueryFn(async (sql, params) => {
    if (sql.startsWith('SELECT')) {
      const r = store.find((x) => x.key_id === params?.key_id);
      return r ? [{ key_id: r.key_id, org_id: r.org_id, scopes: [...r.scopes], owner_kind: r.owner_kind }] : [];
    }
    updates.push({ sql, params: params ?? {} });
    const hits = store.filter((r) => r.key_id === params?.key_id && r.org_id === params?.org_id);
    if (sql.includes('SET owner_kind')) {
      for (const r of hits) r.owner_kind = params?.owner_kind;
      return hits.map((r) => ({ key_id: r.key_id, owner_kind: r.owner_kind }));
    }
    for (const r of hits) r.scopes = [...new Set([...(r.scopes ?? []), ...(params?.add ?? [])])];
    return hits.map((r) => ({ key_id: r.key_id, scopes: [...r.scopes] }));
  });
});
afterEach(() => { setQueryFn(null); setIssueQueryFn(null); setValidationQueryFn(null); });

describe('a person key', () => {
  test('MUST-FAIL: an admin marks a key a person\'s; only that field changes, and the key then validates as person', async () => {
    const admin = await mint(['read', 'write', 'admin'], 'substrate-admin');
    const target = await mint(['read', 'write'], 'a-dashboard-key');
    const before = JSON.parse(JSON.stringify(rowOf(target.keyId)));
    expect((await validateKey(target.key)).ownerKind).toBe('unclassified');
    const r = await grantKeyScopes({ type: 'apiKey_write', key_id: target.keyId, owner_kind: 'person' }, `ApiKey ${admin.key}`);
    expect(r).toMatchObject({ ok: true, owner_kind: 'person', changed: true, added: [] });
    expect(updates).toHaveLength(1);
    expect(updates[0].sql.split(/\bSET\b/)[1].split(/\bWHERE\b/)[0].trim()).toBe('owner_kind = $owner_kind');
    expect(updates[0].sql).toContain('WHERE key_id = $key_id AND org_id = $org_id');
    expect({ ...rowOf(target.keyId), owner_kind: undefined }).toEqual({ ...before, owner_kind: undefined });
    expect((await validateKey(target.key)).ownerKind).toBe('person');
    // marking it again writes nothing
    const again = await grantKeyScopes({ type: 'apiKey_write', key_id: target.keyId, owner_kind: 'person' }, `ApiKey ${admin.key}`);
    expect(again).toMatchObject({ ok: true, changed: false, owner_kind: 'person' });
    expect(updates).toHaveLength(1);
  });

  test('a key that is not admin cannot mark one, nor itself (a guard: the parent refuses the field outright)', async () => {
    const plain = await mint(['read', 'write'], 'a-dashboard-key');
    const r = await grantKeyScopes({ type: 'apiKey_write', key_id: plain.keyId, owner_kind: 'person' }, `ApiKey ${plain.key}`);
    expect(r.ok).toBe(false);
    expect(updates).toHaveLength(0);
    expect(rowOf(plain.keyId).owner_kind).not.toBe('person');
  });

  test('only person or operator may be marked, and a pointer marking nothing is refused (a guard, as above)', async () => {
    const admin = await mint(['read', 'write', 'admin'], 'substrate-admin');
    const target = await mint(['read', 'write'], 'a-dashboard-key');
    for (const owner_kind of ['system', 'peer', 'admin', 'unclassified', '', 1]) {
      const r = await grantKeyScopes({ type: 'apiKey_write', key_id: target.keyId, owner_kind }, `ApiKey ${admin.key}`);
      expect(r).toMatchObject({ ok: false, status: 400 });
    }
    expect(await grantKeyScopes({ type: 'apiKey_write', key_id: target.keyId }, `ApiKey ${admin.key}`)).toMatchObject({ ok: false, status: 400 });
    expect(updates).toHaveLength(0);
  });

  test('a person key is never derived from a name nor declared at issue (a guard)', () => {
    expect(OWNER_KINDS).toContain('person');
    for (const name of ['person', 'avi', 'substrate-admin', 'a-dashboard-key', '']) expect(deriveOwnerKind(name)).not.toBe('person');
    expect(ownerKindAtIssue('anything', 'person')).toBeNull();
  });
});
