/**
 * Tests for the apiKey_write resolver (admin-only scope add, no rotation).
 *
 * The grant runs on identity's root connection, where record PERMISSIONS do not apply
 * (and the live api_key table carries none). So the database here PERMITS every write
 * whose WHERE clause matches: no stub-side refusal. Every refusal below must come from
 * the resolver's own code.
 *
 * Rows have the LIVE shape: each key is minted by the real mintApiKey (issue-key.ts)
 * and the row is exactly the fields its CREATE sets (key_id, key_hash, org_id, user_id,
 * scopes, prefix, created_at, is_active, name), so "only scopes changes" is checked on
 * the fields a real row carries, prefix and key_hash included.
 *
 * MUST-FAIL on a tree without the resolver: an admin adds tools-exec to an existing
 * key, every other field of the row is unchanged, and the same key value then
 * validates WITH tools-exec.
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
  query: async () => {
    throw new Error('SurrealDB query stubbed in grant-scope test');
  },
  getSurrealDB: async () => {
    throw new Error('SurrealDB stubbed in grant-scope test');
  },
}));

import { grantKeyScopes, setQueryFn, GRANTABLE_SCOPES } from './grant-scope';
import { mintApiKey, setQueryFn as setIssueQueryFn } from './issue-key';
import { setQueryFn as setValidationQueryFn, validateKey } from '../services/validation';
import { sign as signJwt } from 'hono/jwt';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
const ORG = 'organizations:alpha';
const OTHER_ORG = 'organizations:beta';
const WHERE = 'WHERE key_id = $key_id AND org_id = $org_id';

let store: Record<string, any>[] = [];
let reads = 0;
let updates: Array<{ sql: string; params: Record<string, any> }> = [];

/** Mint a key through the real issue path and keep the row its CREATE wrote. */
async function mint(org: string, user: string, scopes: string[], name?: string): Promise<{ key: string; keyId: string }> {
  let created: Record<string, any> | null = null;
  setIssueQueryFn(async (sql, params) => {
    expect(sql).toStartWith('CREATE api_key SET');
    created = { ...(params ?? {}) };
    return [];
  });
  const r = await mintApiKey({ org_id: org, user_id: user, scopes, ...(name ? { name } : {}) });
  setIssueQueryFn(null);
  if (!r.ok || !created) throw new Error('mint failed');
  store.push({ ...(created as Record<string, any>), created_at: '2026-10-01T00:00:00Z', is_active: true });
  return { key: r.key, keyId: r.key_id };
}
const rowOf = (keyId: string) => store.find((r) => r.key_id === keyId)!;
const snapshot = (keyId: string) => JSON.parse(JSON.stringify(rowOf(keyId)));

beforeEach(() => {
  store = [];
  reads = 0;
  updates = [];
  // validateKey's lookup: SELECT scopes ... WHERE key_id = $key_id OR key_prefix = $key_id
  setValidationQueryFn(async (_sql, params) => {
    const r = store.find((x) => x.key_id === params?.key_id);
    return r ? [{ scopes: [...r.scopes] }] : [];
  });
  // The root connection: no PERMISSIONS. A SELECT reads; an UPDATE applies to every row its
  // WHERE (key_id AND org_id) matches, and returns the RETURN projection.
  setQueryFn(async (sql, params) => {
    if (sql.startsWith('SELECT')) {
      reads++;
      const r = store.find((x) => x.key_id === params?.key_id);
      return r ? [{ key_id: r.key_id, org_id: r.org_id, scopes: [...r.scopes] }] : [];
    }
    expect(sql).toStartWith('UPDATE api_key SET');
    expect(sql).toContain(WHERE);
    updates.push({ sql, params: params ?? {} });
    const hits = store.filter((r) => r.key_id === params?.key_id && r.org_id === params?.org_id);
    for (const r of hits) r.scopes = [...new Set([...(r.scopes ?? []), ...(params?.add ?? [])])];
    return hits.map((r) => ({ key_id: r.key_id, scopes: [...r.scopes] }));
  });
});
afterEach(() => {
  setQueryFn(null);
  setIssueQueryFn(null);
  setValidationQueryFn(null);
});

describe('apiKey_write — admin-only scope add, no rotation, every guard in code', () => {
  test('MUST-FAIL: an admin adds tools-exec; every other field of the live-shape row is unchanged; the key validates with it', async () => {
    const admin = await mint(ORG, 'users:sys', ['read', 'write', 'admin'], 'substrate-admin');
    const target = await mint(ORG, 'users:sys', ['read', 'write'], 'goal-host-vessel');
    const before = snapshot(target.keyId);
    expect(before.prefix).toBeDefined();
    expect(before.key_hash).toMatch(/^[0-9a-f]{64}$/);

    const r = await grantKeyScopes({ type: 'apiKey_write', key_id: target.keyId, add_scopes: ['tools-exec'] }, `ApiKey ${admin.key}`);

    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.changed).toBe(true);
      expect(r.added).toEqual(['tools-exec']);
      expect(r.scopes).toEqual(['read', 'write', 'tools-exec']);
      // No key material in the result.
      expect(JSON.stringify(r)).not.toContain(before.key_hash);
      expect(JSON.stringify(r)).not.toContain(target.key);
    }
    const after = snapshot(target.keyId);
    expect(after.scopes).toEqual(['read', 'write', 'tools-exec']);
    expect({ ...after, scopes: undefined }).toEqual({ ...before, scopes: undefined });

    const v = await validateKey(target.key);
    expect(v.valid).toBe(true);
    expect(v.keyId).toBe(target.keyId);
    expect(v.scopes).toEqual(['read', 'write', 'tools-exec']);

    // One UPDATE: SET scopes only, guarded by key_id AND the admin's org, returning no hash.
    expect(updates).toHaveLength(1);
    const setClause = updates[0].sql.split(/\bSET\b/)[1].split(/\bWHERE\b/)[0];
    expect(setClause.trim()).toBe('scopes = array::union(scopes ?? [], $add)');
    expect(updates[0].sql).toContain('RETURN key_id, scopes');
    expect(updates[0].params.org_id).toBe(ORG);
    expect(Object.keys(updates[0].params).sort()).toEqual(['add', 'key_id', 'org_id']);
  });

  test('MUST-FAIL: a cross-org admin is refused by the code (403, no UPDATE sent), though the database would permit it', async () => {
    const admin = await mint(ORG, 'users:sys', ['read', 'write', 'admin']);
    const foreign = await mint(OTHER_ORG, 'users:other', ['read', 'write']);
    const before = snapshot(foreign.keyId);
    const r = await grantKeyScopes({ key_id: foreign.keyId, add_scopes: ['tools-exec'] }, `ApiKey ${admin.key}`);
    expect(r.ok).toBe(false);
    if (!r.ok) { expect(r.status).toBe(403); expect(r.code).toBe('FORBIDDEN'); }
    expect(updates).toHaveLength(0);
    expect(snapshot(foreign.keyId)).toEqual(before);
  });

  test('MUST-FAIL: a non-admin caller is refused by the code (403, no read, no UPDATE), though the database would permit it', async () => {
    const caller = await mint(ORG, 'users:sys', ['read', 'write']);
    const target = await mint(ORG, 'users:sys', ['read', 'write']);
    const before = snapshot(target.keyId);
    for (const auth of [`ApiKey ${caller.key}`, `ApiKey ${target.key}`]) {   // another key, and the key itself
      const r = await grantKeyScopes({ key_id: target.keyId, add_scopes: ['tools-exec'] }, auth);
      expect(r.ok).toBe(false);
      if (!r.ok) { expect(r.status).toBe(403); expect(r.code).toBe('FORBIDDEN'); expect(r.message).toBe('API key does not have admin scope'); }
    }
    const member = await signJwt({ org_id: ORG, user_id: 'users:m', role: 'member', exp: Math.floor(Date.now() / 1000) + 60 }, JWT_SECRET, 'HS512');
    const rj = await grantKeyScopes({ key_id: target.keyId, add_scopes: ['tools-exec'] }, `Bearer ${member}`);
    expect(rj.ok).toBe(false);
    if (!rj.ok) expect(rj.status).toBe(403);
    expect(reads).toBe(0);
    expect(updates).toHaveLength(0);
    expect(snapshot(target.keyId)).toEqual(before);
  });

  test('a row with NO stored scopes (validates as read, write) keeps read and write when tools-exec is added', async () => {
    const admin = await mint(ORG, 'users:sys', ['read', 'write', 'admin']);
    const target = await mint(ORG, 'users:sys', []);
    expect((await validateKey(target.key)).scopes).toBeUndefined(); // the caller's ['read','write'] default applies
    const r = await grantKeyScopes({ key_id: target.keyId, add_scopes: ['tools-exec'] }, `ApiKey ${admin.key}`);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.added).toEqual(['tools-exec']);
    expect((await validateKey(target.key)).scopes).toEqual(['read', 'write', 'tools-exec']);
  });

  test('a Bearer admin JWT may add it too', async () => {
    const target = await mint(ORG, 'users:sys', ['read', 'write']);
    const jwt = await signJwt({ org_id: ORG, user_id: 'users:op', role: 'admin', exp: Math.floor(Date.now() / 1000) + 60 }, JWT_SECRET, 'HS512');
    const r = await grantKeyScopes({ key_id: target.keyId, add_scopes: ['tools-exec'] }, `Bearer ${jwt}`);
    expect(r.ok).toBe(true);
    expect(rowOf(target.keyId).scopes).toContain('tools-exec');
  });

  test('admin requested is refused: the allowlist is a frozen constant without admin', async () => {
    expect(GRANTABLE_SCOPES).toEqual(['tools-exec']);
    expect(Object.isFrozen(GRANTABLE_SCOPES)).toBe(true);
    const admin = await mint(ORG, 'users:sys', ['read', 'write', 'admin']);
    const target = await mint(ORG, 'users:sys', ['read', 'write']);
    for (const add of [['admin'], ['tools-exec', 'admin'], ['verdict-corpus:write']]) {
      const r = await grantKeyScopes({ key_id: target.keyId, add_scopes: add }, `ApiKey ${admin.key}`);
      expect(r.ok).toBe(false);
      if (!r.ok) { expect(r.status).toBe(403); expect(r.code).toBe('SCOPE_NOT_GRANTABLE'); }
    }
    expect(rowOf(target.keyId).scopes).toEqual(['read', 'write']);
    expect(updates).toHaveLength(0);
  });

  test('a removal, replacement or rotation attempt is refused', async () => {
    const admin = await mint(ORG, 'users:sys', ['read', 'write', 'admin']);
    const target = await mint(ORG, 'users:sys', ['read', 'write', 'tools-exec']);
    const before = snapshot(target.keyId);
    for (const p of [
      { key_id: target.keyId, remove_scopes: ['tools-exec'] },
      { key_id: target.keyId, scopes: ['read'] },
      { key_id: target.keyId, add_scopes: ['tools-exec'], remove_scopes: ['write'] },
    ]) {
      const r = await grantKeyScopes(p, `ApiKey ${admin.key}`);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.code).toBe('REMOVAL_REFUSED');
    }
    for (const extra of [{ key_hash: 'x' }, { prefix: 'mb-x' }, { name: 'n' }]) {
      const r = await grantKeyScopes({ key_id: target.keyId, add_scopes: ['tools-exec'], ...extra }, `ApiKey ${admin.key}`);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.code).toBe('INVALID_INPUT');
    }
    expect(snapshot(target.keyId)).toEqual(before);
    expect(updates).toHaveLength(0);
  });

  test('a second add is a no-op: no UPDATE, changed false', async () => {
    const admin = await mint(ORG, 'users:sys', ['read', 'write', 'admin']);
    const target = await mint(ORG, 'users:sys', ['read', 'write']);
    const p = { key_id: target.keyId, add_scopes: ['tools-exec'] };
    const first = await grantKeyScopes(p, `ApiKey ${admin.key}`);
    const second = await grantKeyScopes(p, `ApiKey ${admin.key}`);
    expect(first.ok && first.changed).toBe(true);
    expect(second.ok).toBe(true);
    if (second.ok) { expect(second.changed).toBe(false); expect(second.added).toEqual([]); }
    expect(rowOf(target.keyId).scopes).toEqual(['read', 'write', 'tools-exec']);
    expect(updates).toHaveLength(1);
  });

  test('an unknown key_id is NOT_FOUND, and an UPDATE that matches nothing is PERSIST_FAILED, never a success', async () => {
    const admin = await mint(ORG, 'users:sys', ['read', 'write', 'admin']);
    const r = await grantKeyScopes({ key_id: 'key_nope', add_scopes: ['tools-exec'] }, `ApiKey ${admin.key}`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('NOT_FOUND');
    const target = await mint(ORG, 'users:sys', ['read', 'write']);
    setQueryFn(async (sql) => (sql.startsWith('SELECT') ? [{ key_id: target.keyId, org_id: ORG, scopes: ['read', 'write'] }] : []));
    const gone = await grantKeyScopes({ key_id: target.keyId, add_scopes: ['tools-exec'] }, `ApiKey ${admin.key}`);
    expect(gone.ok).toBe(false);
    if (!gone.ok) { expect(gone.status).toBe(500); expect(gone.code).toBe('PERSIST_FAILED'); }
  });

  test('the audit line names key_id and the scope, never a key value or hash', async () => {
    const admin = await mint(ORG, 'users:sys', ['read', 'write', 'admin']);
    const target = await mint(ORG, 'users:sys', ['read', 'write']);
    const lines: string[] = [];
    const orig = console.log;
    console.log = (...a: unknown[]) => { lines.push(a.map((x) => typeof x === 'string' ? x : JSON.stringify(x)).join(' ')); };
    try {
      await grantKeyScopes({ key_id: target.keyId, add_scopes: ['tools-exec'] }, `ApiKey ${admin.key}`);
    } finally {
      console.log = orig;
    }
    const audit = lines.filter((l) => l.includes('[ScopeGrant]'));
    expect(audit).toHaveLength(1);
    expect(audit[0]).toContain(target.keyId);
    expect(audit[0]).toContain('tools-exec');
    for (const l of lines) {
      for (const secret of [admin.key, target.key, rowOf(admin.keyId).key_hash, rowOf(target.keyId).key_hash]) expect(l).not.toContain(secret);
    }
  });
});
