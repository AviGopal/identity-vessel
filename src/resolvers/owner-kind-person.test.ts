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
  store.push({ id: `api_key:rec${++recs}`, ...(created as Record<string, any>), is_active: true });
  return { key: r.key, keyId: r.key_id };
}
// A row is found by its id as validation finds it: in key_id, or in key_prefix on a row written before key_id was stored.
// The database finds what the SQL names: key_id; the record id when the query names record::id(id);
// key_prefix only when the query names it.
const asQueried = (sql: string) => (r: Record<string, any>, id: unknown) =>
  r.key_id === id || (sql.includes('record::id(id) = $key_id') && r.id === `api_key:${String(id)}`)
  || (sql.includes('key_prefix = $key_id') && r.key_prefix === id);
const rowOf = (keyId: string) => store.find((r) => r.key_id === keyId || r.id === `api_key:${keyId}`)!;
let recs = 0;

beforeEach(() => {
  store = [];
  updates = [];
  setValidationQueryFn(async (_sql, params) => {
    const r = store.find((x) => asQueried(_sql)(x, params?.key_id));
    return r ? [{ scopes: [...r.scopes], name: r.name, owner_kind: r.owner_kind }] : [];
  });
  setQueryFn(async (sql, params) => {
    const match = asQueried(sql);
    if (sql.startsWith('SELECT')) {
      const r = store.find((x) => match(x, params?.key_id));
      return r ? [{ id: r.id, key_id: r.key_id, org_id: r.org_id, scopes: [...r.scopes], owner_kind: r.owner_kind }] : [];
    }
    updates.push({ sql, params: params ?? {} });
    // a write names its record ($rid), or (the parent's form) every row its WHERE matches
    const hits = sql.startsWith('UPDATE $rid')
      ? store.filter((r) => r.id === params?.rid && r.org_id === params?.org_id)
      : store.filter((r) => match(r, params?.key_id) && r.org_id === params?.org_id);
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
    expect(updates[0].sql).toStartWith('UPDATE $rid SET');
    expect(updates[0].sql).toContain('WHERE org_id = $org_id');
    expect(updates[0].params.rid).toBe(before.id);
    expect({ ...rowOf(target.keyId), owner_kind: undefined }).toEqual({ ...before, owner_kind: undefined });
    expect((await validateKey(target.key)).ownerKind).toBe('person');
    // marking it again writes nothing
    const again = await grantKeyScopes({ type: 'apiKey_write', key_id: target.keyId, owner_kind: 'person' }, `ApiKey ${admin.key}`);
    expect(again).toMatchObject({ ok: true, changed: false, owner_kind: 'person' });
    expect(updates).toHaveLength(1);
  });

  test('MUST-FAIL: an old-format key (no key_id; its id in its record id, its key_prefix the key itself) is found by id and marked', async () => {
    const admin = await mint(['read', 'write', 'admin'], 'substrate-admin');
    const id = 'key__legacyFixture01';
    store.push({ id: `api_key:${id}`, org_id: ORG, user_id: 'users:sys', scopes: ['read', 'write'], name: 'a-surface-key', key_prefix: 'mb_the_key_itself_never_matched', is_active: true });
    const r = await grantKeyScopes({ type: 'apiKey_write', key_id: id, owner_kind: 'person' }, `ApiKey ${admin.key}`);
    expect(r).toMatchObject({ ok: true, owner_kind: 'person', changed: true });
    expect(rowOf(id).owner_kind).toBe('person');
    expect(updates).toHaveLength(1);
    expect(updates[0].params.rid).toBe(`api_key:${id}`);
    expect(JSON.stringify(r)).not.toContain('mb_the_key_itself'); // the key itself is never echoed
  });

  test('MUST-FAIL: a value many rows hold as key_prefix finds no key, and marks none of them', async () => {
    const admin = await mint(['read', 'write', 'admin'], 'substrate-admin');
    for (const n of [1, 2]) store.push({ id: `api_key:dup${n}`, org_id: ORG, user_id: 'users:sys', scopes: ['read', 'write'], key_prefix: 'dup', is_active: true });
    const r = await grantKeyScopes({ type: 'apiKey_write', key_id: 'dup', owner_kind: 'person' }, `ApiKey ${admin.key}`);
    expect(r).toMatchObject({ ok: false, status: 404 });
    expect(store.filter((x) => x.owner_kind === 'person')).toHaveLength(0);
    expect(updates).toHaveLength(0);
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
