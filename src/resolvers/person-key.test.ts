/**
 * A person makes their own key: a person-session token from the ApiKey they signed in with, and under it one new key,
 * stamped person at insert, returned once. The token is accepted nowhere else; nothing else is accepted at the mint;
 * no existing row is changed. The database is stubbed; keys are minted through the real generator.
 */
import { test, expect, describe, beforeEach, afterEach, mock, spyOn } from 'bun:test';

const revoked = new Set<string>();
mock.module('../db/redis', () => ({
  redis: {},
  isKeyRevoked: async (id: string) => revoked.has(id),
  revokeKey: async () => {},
  unrevokeKey: async () => {},
  getRateLimitKey: (endpoint: string, ip: string) => `ratelimit:${endpoint}:${ip}`,
  checkRateLimit: async () => ({ allowed: true, retryAfterSeconds: 0 }),
}));
mock.module('../db/surrealdb', () => ({
  query: async () => { throw new Error('SurrealDB query stubbed'); },
  getSurrealDB: async () => { throw new Error('SurrealDB stubbed'); },
}));

import { sign } from 'hono/jwt';
import { issuePersonSession, issuePersonKey, PERSON_SESSION_TYP, __resetPersonKeyForTests } from './person-key';
import { setQueryFn as setIssueQueryFn, authorizeAdmin } from './issue-key';
import { setQueryFn as setValidationQueryFn } from '../services/validation';
import { generateApiKey } from '../services/keyGeneration';
import { generateToken, verifyToken } from '../services/jwt';
import { resolveAuthentication } from './auth';
import { mintOnBehalfOf } from '../services/obo';
import { createdRow } from '../db/created-row.test-helper';
import { readKeyClass, setQueryFn as setClassQueryFn } from './key-class';
import { validateKey } from '../services/validation';
import { __resetAnswerLogForTests, heldAnswers } from '../services/answer-log';

const ORG = 'organizations:alpha';
const USER = 'users:one';
const SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
let sourceRow: Record<string, unknown> = {};
let statements: string[] = [];
let logged: string[] = [];
let spy: ReturnType<typeof spyOn>;

beforeEach(() => {
  revoked.clear();
  __resetPersonKeyForTests();
  statements = [];
  logged = [];
  sourceRow = { id: 'api_key:signinrw', scopes: ['read', 'write'], name: 'my laptop', owner_kind: 'unclassified' };
  setValidationQueryFn(async (_sql, params) => [{ ...sourceRow, key_id: params?.key_id }]);
  setIssueQueryFn(async (sql, params) => { statements.push(sql); return createdRow(sql, params); });
  spy = spyOn(console, 'log').mockImplementation((...a: unknown[]) => { logged.push(a.map(String).join(' ')); });
});
afterEach(() => { spy.mockRestore(); setValidationQueryFn(null); setIssueQueryFn(null); });

const signIn = () => generateApiKey(ORG, USER, {});
async function session(): Promise<string> {
  const r = await issuePersonSession(`ApiKey ${signIn().key}`);
  if (!r.ok) throw new Error(`no session: ${r.message}`);
  return r.token;
}

describe('a person makes their own key', () => {
  test('a sign-in token, then one new key: person at insert, read and write, for the token user and org', async () => {
    const token = await session();
    const made = await issuePersonKey(`Bearer ${token}`);
    expect(made.ok).toBe(true);
    if (!made.ok) return;
    expect(made.key.startsWith('mb-')).toBe(true);
    expect(statements).toHaveLength(1);
    expect(statements[0]).toMatch(/^CREATE api_key SET/);
    const created = createdRowParams();
    expect(created).toMatchObject({ owner_kind: 'person', scopes: ['read', 'write'], name: 'person-key', org_id: ORG, user_id: USER });
    expect(created.key_id).toBe(made.key_id);
  });

  test('MUST-FAIL: no existing row is changed: one CREATE, never an UPDATE, a DELETE or an UPSERT', async () => {
    const token = await session();
    await issuePersonKey(`Bearer ${token}`);
    expect(statements.filter((s) => /\b(UPDATE|DELETE|UPSERT|RELATE|INSERT)\b/i.test(s))).toEqual([]);
  });

  test('MUST-FAIL: the key and the token are never logged', async () => {
    const token = await session();
    const made = await issuePersonKey(`Bearer ${token}`);
    if (!made.ok) throw new Error('not made');
    const all = logged.join('\n');
    expect(all).not.toContain(made.key);
    expect(all).not.toContain(made.key_id);
    expect(all).not.toContain(token);
  });

  test('MUST-FAIL: one key per sign-in token, refused as ALREADY_MINTED', async () => {
    const token = await session();
    expect((await issuePersonKey(`Bearer ${token}`)).ok).toBe(true);
    const again = await issuePersonKey(`Bearer ${token}`);
    expect(again.ok).toBe(false);
    expect((again as { code?: string }).code).toBe('ALREADY_MINTED');
    expect(statements).toHaveLength(1);
  });

  test('MUST-FAIL: the new row names the key the person signed in with, and when', async () => {
    const k = signIn();
    const r = await issuePersonSession(`ApiKey ${k.key}`);
    if (!r.ok) throw new Error('no session');
    const made = await issuePersonKey(`Bearer ${r.token}`);
    expect(made.ok).toBe(true);
    expect(createdRowParams().minted_from).toBe(k.keyId);
    expect(statements[0]).toContain('minted_from = $minted_from');
    expect(statements[0]).toContain('minted_at = time::now()');
  });

  test('a mint that made no row gives the token its share back', async () => {
    const token = await session();
    setIssueQueryFn(async (sql) => { statements.push(sql); return []; });
    expect((await issuePersonKey(`Bearer ${token}`)).ok).toBe(false);
    setIssueQueryFn(async (sql, params) => { statements.push(sql); lastParams = { ...(params ?? {}) }; return createdRow(sql, params); });
    expect((await issuePersonKey(`Bearer ${token}`)).ok).toBe(true);
  });

  test("MUST-FAIL: the listing and keyAnswer show a made key's source, and only a made key's", async () => {
    __resetAnswerLogForTests();
    const reader = signIn();
    const k = signIn();
    const minted = { id: 'api_key:mintedrw', key_id: 'key_mintedkeyvalue01', org_id: ORG, name: 'person-key', scopes: ['read', 'write'], owner_kind: 'person', minted_from: k.keyId };
    const plain = { id: 'api_key:plainrow', key_id: 'key_plainkeyvalue001', org_id: ORG, name: 'my laptop', scopes: ['read', 'write'], owner_kind: 'unclassified' };
    setClassQueryFn(async () => [minted, plain]);
    const listed = await readKeyClass(`ApiKey ${reader.key}`);
    setClassQueryFn(null);
    if (!listed.ok) throw new Error('listing refused');
    expect(listed.keys.find((e) => e.key_id_mask12 === 'key_mintedke')?.minted_from_mask12).toBe(k.keyId.slice(0, 12));
    expect('minted_from_mask12' in listed.keys.find((e) => e.key_id_mask12 === 'key_plainkey')!).toBe(false);
    const p = generateApiKey(ORG, USER, {});
    sourceRow = { id: 'api_key:mintedrw', name: 'person-key', scopes: ['read', 'write'], owner_kind: 'person', minted_from: k.keyId };
    await validateKey(p.key);
    expect(heldAnswers(ORG).find((h) => h.kind === 'key' && h.key_mask12 === p.keyId.slice(0, 12))).toMatchObject({ minted_from_mask12: k.keyId.slice(0, 12), answered: 'person' });
  });
});

describe('the mint takes nothing but a person session', () => {
  test('MUST-FAIL: an ApiKey caller cannot mint a person key', async () => {
    const r = await issuePersonKey(`ApiKey ${signIn().key}`);
    expect(r.ok).toBe(false);
    expect(statements).toEqual([]);
  });

  test('MUST-FAIL: an on-behalf-of token cannot mint a person key', async () => {
    const now = Math.floor(Date.now() / 1000);
    const obo = await sign({ typ: 'obo', sub: USER, user_id: USER, org_id: ORG, key_id: 'key_x', jti: 'j1', aud: 'substrate:n', obo_shape: 's', iat: now, exp: now + 60 }, SECRET, 'HS512');
    expect((await issuePersonKey(`Bearer ${obo}`)).ok).toBe(false);
    expect(statements).toEqual([]);
  });

  test('MUST-FAIL: a general session token cannot mint a person key', async () => {
    const general = await generateToken({ user_id: USER, org_id: ORG, role: 'member' } as any);
    expect((await issuePersonKey(`Bearer ${general.token}`)).ok).toBe(false);
    expect(statements).toEqual([]);
  });

  test('MUST-FAIL: a token of no person-session type cannot mint, even naming a user, an org, a key and a one-time id', async () => {
    const now = Math.floor(Date.now() / 1000);
    const typeless = await sign({ sub: USER, user_id: USER, org_id: ORG, key_id: 'key_x', jti: 'j2', iat: now, exp: now + 60 }, SECRET, 'HS512');
    expect((await issuePersonKey(`Bearer ${typeless}`)).ok).toBe(false);
    expect(statements).toEqual([]);
  });

  test('MUST-FAIL: an expired person session cannot mint', async () => {
    const past = Math.floor(Date.now() / 1000) - 3600;
    const stale = await sign({ typ: PERSON_SESSION_TYP, sub: USER, user_id: USER, org_id: ORG, key_id: 'key_x', jti: 'j', iat: past, exp: past + 300 }, SECRET, 'HS512');
    expect((await issuePersonKey(`Bearer ${stale}`)).ok).toBe(false);
    expect(statements).toEqual([]);
  });
});

describe('a sign-in token is a person\'s only', () => {
  test('MUST-FAIL: a system-named, admin-named, admin-scoped, system-class or peer-class key gets no person session', async () => {
    for (const row of [
      { name: 'local-tools-vessel', scopes: ['read', 'write'] },
      { name: 'substrate-admin-bootstrap', scopes: ['read', 'write'] },
      { name: 'my laptop', scopes: ['read', 'write', 'admin'] },
      { name: 'my laptop', scopes: ['read', 'write'], owner_kind: 'system' },
      { name: 'my laptop', scopes: ['read', 'write'], owner_kind: 'peer' },
    ]) {
      sourceRow = { id: 'api_key:signinrw', ...row };
      const r = await issuePersonSession(`ApiKey ${signIn().key}`);
      expect([row.name, r.ok]).toEqual([row.name, false]);
    }
  });

  test('the token is short-lived and names the user, the org and the key it came from', async () => {
    const k = signIn();
    const r = await issuePersonSession(`ApiKey ${k.key}`);
    if (!r.ok) throw new Error('no session');
    const payload = JSON.parse(Buffer.from(r.token.split('.')[1], 'base64url').toString());
    expect(payload).toMatchObject({ typ: PERSON_SESSION_TYP, user_id: USER, org_id: ORG, key_id: k.keyId });
    expect(payload.exp - payload.iat).toBeLessThanOrEqual(300);
  });
});

describe('a revoked key makes nothing', () => {
  test('MUST-FAIL: a revoked key gets no person session, and so no key', async () => {
    const k = signIn();
    revoked.add(k.keyId);
    const r = await issuePersonSession(`ApiKey ${k.key}`);
    expect(r.ok).toBe(false);
    expect(statements).toEqual([]);
  });

  test('MUST-FAIL: a key revoked after its sign-in token was minted cannot mint under it', async () => {
    const k = signIn();
    const r = await issuePersonSession(`ApiKey ${k.key}`);
    if (!r.ok) throw new Error('no session');
    revoked.add(k.keyId);
    const made = await issuePersonKey(`Bearer ${r.token}`);
    expect(made.ok).toBe(false);
    expect(statements).toEqual([]);
  });

  test('MUST-FAIL: a Bearer token (an on-behalf-of or a person session) gets no person session', async () => {
    const token = await session();
    expect((await issuePersonSession(`Bearer ${token}`)).ok).toBe(false);
  });
});

describe('a person session token is refused at every other door', () => {
  test('MUST-FAIL: verifyToken (the JWT doors), auth resolve, the OBO mint and admin authorization each refuse it', async () => {
    const token = await session();
    expect((await verifyToken(token)).valid).toBe(false);
    const resolved = await resolveAuthentication({ type: 'authentication', pointer: { type: 'session', token } } as any);
    expect(resolved.authenticated).toBe(false);
    const obo = await mintOnBehalfOf(`ApiKey ${signIn().key}`, `Bearer ${token}`, { node: 'n', shape: 's' });
    expect('token' in obo).toBe(false);
    const admin = await authorizeAdmin(`Bearer ${token}`);
    expect('ok' in admin && (admin as { ok: boolean }).ok === true).toBe(false);
  });
});

/** The params the one CREATE was sent with, as the stub saw them. */
let lastParams: Record<string, any> = {};
function createdRowParams(): Record<string, any> { return lastParams; }
beforeEach(() => {
  setIssueQueryFn(async (sql, params) => { statements.push(sql); lastParams = { ...(params ?? {}) }; return createdRow(sql, params); });
});
