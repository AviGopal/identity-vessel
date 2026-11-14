/**
 * Each key answer is held as a fact (branch, how its row was found, the row, the stored class, the class answered), one
 * entry per key, and served by keyAnswer to a service key of the same org, with the node and the time this identity
 * started holding answers; an empty answer says so in words. Nothing held holds a key or a key_prefix value.
 * The HMAC branch runs through validateKey with a real minted key and the query stubbed; the legacy branch through the
 * auth resolver with the database module stubbed; the delegated branch in a process of its own.
 */
import { test, expect, describe, beforeEach, afterEach, mock } from 'bun:test';

let legacyRows: Record<string, any>[] | Error = [];
mock.module('../db/redis', () => ({
  redis: {},
  isKeyRevoked: async () => false,
  revokeKey: async () => {},
  unrevokeKey: async () => {},
  getRateLimitKey: (endpoint: string, ip: string) => `ratelimit:${endpoint}:${ip}`,
  checkRateLimit: async () => ({ allowed: true, retryAfterSeconds: 0 }),
}));
mock.module('../db/surrealdb', () => ({
  query: async () => { if (legacyRows instanceof Error) throw legacyRows; return legacyRows; },
  getSurrealDB: async () => { throw new Error('SurrealDB stubbed'); },
}));

import { validateKey, setQueryFn } from './validation';
import { generateApiKey } from './keyGeneration';
import { resolveAuthentication } from '../resolvers/auth';
import { __resetAnswerLogForTests, heldAnswers, heldSince, recordOboMint, recordKeyAnswer, MINT_ANSWERS_HELD, MINT_ANSWERS_PER_KEY } from './answer-log';
import { mintOnBehalfOf } from './obo';
import { readKeyAnswer } from '../resolvers/key-answer';
import { readKeyClass, setQueryFn as setClassQueryFn } from '../resolvers/key-class';
import { join } from 'node:path';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';

const ORG = 'organizations:alpha';
const PLANTED_PREFIX = 'plantedprefixvaluethatmustneverprint';

beforeEach(() => { __resetAnswerLogForTests(); });
afterEach(() => { setQueryFn(null); legacyRows = []; });

const minted = () => generateApiKey(ORG, 'users:one', {});
const held = () => heldAnswers(ORG);
const strip = (a: Record<string, unknown>) => { const { at: _at, ...rest } = a; return rest; };

describe('hmac branch', () => {
  test('a row found by key_id: its class, the row, and how it was found', async () => {
    const g = minted();
    setQueryFn(async () => [{ id: 'api_key:recordone', key_id: g.keyId, key_prefix: PLANTED_PREFIX, scopes: ['read'], name: 'n', owner_kind: 'person' }]);
    const v = await validateKey(g.key);
    expect(v.ownerKind).toBe('person');
    expect(held().map(strip)).toEqual([{ kind: 'key', key_mask12: g.keyId.slice(0, 12), branch: 'hmac', found_by: 'key_id', row_mask8: 'recordon', stored: 'person', answered: 'person' }]);
  });

  test('a row found by its record id, its key_id empty', async () => {
    const g = minted();
    setQueryFn(async () => [{ id: `api_key:${g.keyId}`, scopes: ['read'], name: 'n', owner_kind: 'operator' }]);
    await validateKey(g.key);
    expect(held()[0]).toMatchObject({ found_by: 'record_id', answered: 'operator' });
  });

  test('a row found by neither key_id nor record id was found by key_prefix', async () => {
    const g = minted();
    setQueryFn(async () => [{ id: 'api_key:otherrow', key_id: 'key_someotherkeyid', scopes: ['read'], name: 'n' }]);
    await validateKey(g.key);
    expect(held()[0]).toMatchObject({ found_by: 'key_prefix', row_mask8: 'otherrow', stored: 'none', answered: 'unclassified' });
  });

  test('a stored owner_kind that is not a class reads "invalid", and the class answered is derived', async () => {
    const g = minted();
    setQueryFn(async () => [{ id: 'api_key:recordone', key_id: g.keyId, scopes: ['read'], name: 'n', owner_kind: 'Person' }]);
    await validateKey(g.key);
    expect(held()[0]).toMatchObject({ stored: 'invalid', answered: 'unclassified' });
  });

  test('no row, two rows, and a failed read are each held', async () => {
    const g = minted();
    setQueryFn(async () => []);
    await validateKey(g.key);
    expect(held()[0]).toMatchObject({ found_by: 'none', row_mask8: '-', stored: '-', answered: 'none' });
    setQueryFn(async () => [{ id: 'api_key:a', key_id: g.keyId }, { id: 'api_key:b', key_prefix: g.keyId }]);
    await validateKey(g.key);
    expect(held()[0]).toMatchObject({ found_by: 'ambiguous' });
    setQueryFn(async () => { throw new Error('down'); });
    await validateKey(g.key);
    expect(held()[0]).toMatchObject({ found_by: 'error' });
  });

  test('one entry per key, replaced by its latest answer', async () => {
    const g = minted();
    let kind = 'person';
    setQueryFn(async () => [{ id: 'api_key:recordone', key_id: g.keyId, scopes: ['read'], name: 'n', owner_kind: kind }]);
    await validateKey(g.key);
    await validateKey(g.key);
    expect(held()).toHaveLength(1);
    kind = 'operator';
    await validateKey(g.key);
    expect(held()).toHaveLength(1);
    expect(held()[0]).toMatchObject({ answered: 'operator' });
  });

  test('the selected fields never include key_prefix, and nothing held holds a key or a key_prefix value', async () => {
    const g = minted();
    let sql = '';
    setQueryFn(async (s) => { sql = s; return [{ id: 'api_key:recordone', key_id: g.keyId, key_prefix: PLANTED_PREFIX, scopes: ['read'], owner_kind: 'person' }]; });
    await validateKey(g.key);
    expect(sql.split(' FROM ')[0]).not.toContain('key_prefix');
    const all = JSON.stringify(held());
    expect(all).not.toContain(PLANTED_PREFIX);
    expect(all).not.toContain(g.key);
  });
});

describe('legacy branch', () => {
  const oldKey = 'oldformatkeyfixturevalue';

  test('a row found by its stored prefix: named by its stable id, never by the presented value', async () => {
    legacyRows = [{ id: 'api_key:legacyrow', key_id: 'key_legacykeyidvalue', org_id: ORG, user_id: 'users:one', scopes: ['read'], name: 'n', is_active: true }];
    const r = await resolveAuthentication({ type: 'authentication', pointer: { type: 'apiKey', apiKey: oldKey } } as any);
    expect(r.authenticated).toBe(true);
    expect(held().map(strip)).toEqual([{ kind: 'key', key_mask12: 'key_legacyke', branch: 'legacy', found_by: 'key_prefix', row_mask8: 'legacyro', stored: 'none', answered: 'unclassified' }]);
    expect(JSON.stringify(held())).not.toContain(oldKey.slice(0, 8));
  });

  test('an inactive row is held as inactive, named by its stable id', async () => {
    legacyRows = [{ id: 'api_key:legacyrow', key_id: 'key_legacykeyidvalue', org_id: ORG, is_active: false, owner_kind: 'person' }];
    await resolveAuthentication({ type: 'authentication', pointer: { type: 'apiKey', apiKey: oldKey } } as any);
    expect(held().map(strip)).toEqual([{ kind: 'key', key_mask12: 'key_legacyke', branch: 'legacy', found_by: 'key_prefix', row_mask8: 'legacyro', stored: 'person', answered: 'inactive' }]);
    expect(JSON.stringify(held())).not.toContain(oldKey.slice(0, 8));
  });
});

describe('delegated branch', () => {
  // validation.ts reads its secret and trusted issuers when it loads, so a key from a trusted foreign issuer is
  // validated in a process of its own, with those set and the issuer's answer stubbed.
  test('a key its issuer validated is held as delegated, found by the issuer, with no class; a newline is held as ?', () => {
    const script = `
      const { createHmac } = await import('node:crypto');
      const iss = 'https://issuer.test';
      const payload = 'organizations:alpha-users:one-key_foreignkeyidvalue-' + iss;
      const fin = 'mb-' + Buffer.from(payload).toString('base64url');
      const key = fin + '-' + createHmac('sha256', 'anotherissuersecretvalue').update(fin).digest('hex').slice(0, 32);
      let keyId = 'key_foreignkeyidvalue';
      globalThis.fetch = async () => new Response(JSON.stringify({ success: true, data: { valid: true, org_id: 'organizations:alpha', user_id: 'users:one', key_id: keyId } }));
      const { validateKey } = await import(${JSON.stringify(join(import.meta.dir, 'validation.ts'))});
      const { heldAnswers } = await import(${JSON.stringify(join(import.meta.dir, 'answer-log.ts'))});
      const a = await validateKey(key);
      keyId = 'key_x\\n[KeyAnswer] forged';
      await validateKey(key);
      process.stdout.write(JSON.stringify({ valid: a.valid, ownerKind: a.ownerKind ?? null, held: heldAnswers('organizations:alpha').map(({ at, ...r }) => r) }));
    `;
    const dir = mkdtempSync(join(tmpdir(), 'answer-log-delegated-'));
    const file = join(dir, 'run.ts');
    writeFileSync(file, script);
    const r = Bun.spawnSync([process.execPath, file], {
      env: { ...process.env, API_KEY_SECRET: 'thisnodesownsecretvalue', IDENTITY_ENDPOINT: 'http://127.0.0.1:8101', TRUSTED_ISSUERS: 'https://issuer.test' },
    });
    rmSync(dir, { recursive: true, force: true });
    expect(r.stderr.toString()).toBe('');
    const out = JSON.parse(r.stdout.toString()) as { valid: boolean; ownerKind: string | null; held: Record<string, unknown>[] };
    expect(out.valid).toBe(true);
    expect(out.ownerKind).toBeNull();
    const masks = out.held.map((h) => h.key_mask12).sort();
    expect(masks).toEqual(['key_foreignk', 'key_x??KeyAn']);
    expect(out.held.every((h) => h.branch === 'delegated' && h.found_by === 'issuer' && h.answered === 'none')).toBe(true);
  });
});

describe('on-behalf-of mint', () => {
  test('mintOnBehalfOf holds the class the token carries, through its own call', async () => {
    const actor = minted();
    const caller = minted();
    setQueryFn(async (_sql, params) => [{ id: 'api_key:rowfor', key_id: params?.key_id, scopes: ['read', 'write'], name: 'n', owner_kind: params?.key_id === caller.keyId ? 'person' : 'system' }]);
    const r = await mintOnBehalfOf(`ApiKey ${actor.key}`, `ApiKey ${caller.key}`, { node: 'nodeA', shape: 'record_write' });
    expect('token' in r).toBe(true);
    expect(held().filter((h) => h.kind === 'obo_mint').map(strip)).toEqual([
      { kind: 'obo_mint', key_mask12: caller.keyId.slice(0, 12), scheme: 'api_key', carries: 'person', audience: 'nodeA/record_write' },
    ]);
  });

  test('a node or shape holding a newline is held with ?, and an answer with no org is not held', () => {
    recordOboMint({ scheme: 'session', keyId: undefined, orgId: ORG, ownerKind: undefined, node: 'n\n[OboMint] x', shape: 's' });
    recordOboMint({ scheme: 'session', keyId: undefined, orgId: undefined, ownerKind: undefined, node: 'other', shape: 's' });
    expect(held().map(strip)).toEqual([{ kind: 'obo_mint', key_mask12: '-', scheme: 'session', carries: 'none', audience: 'n??OboMint??x/s' }]);
  });
});

describe('keyAnswer, the shape', () => {
  test('a service key of the org reads its org held answers, with the node and when holding started', async () => {
    const reader = minted();
    const g = minted();
    setQueryFn(async (_sql, params) => [{ id: 'api_key:rowfor', key_id: params?.key_id, scopes: ['read'], name: 'n', owner_kind: params?.key_id === g.keyId ? 'person' : 'system' }]);
    await validateKey(g.key);
    const r = await readKeyAnswer(`ApiKey ${reader.key}`, { type: 'keyAnswer', key_mask: g.keyId.slice(0, 12) });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.held_since).toBe(heldSince());
    expect('node' in r).toBe(true);
    expect(r.none).toBeUndefined();
    expect(r.answers.map(strip)).toEqual([{ kind: 'key', key_mask12: g.keyId.slice(0, 12), branch: 'hmac', found_by: 'key_id', row_mask8: 'rowfor', stored: 'person', answered: 'person' }]);
  });

  test('nothing held for a key says so in words, with the time holding started, never an empty list alone', async () => {
    const reader = minted();
    setQueryFn(async (_sql, params) => [{ id: 'api_key:rowfor', key_id: params?.key_id, scopes: ['read'], name: 'n', owner_kind: 'system' }]);
    const r = await readKeyAnswer(`ApiKey ${reader.key}`, { type: 'keyAnswer', key_mask: 'key_zzzzzzzz' });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.answers).toEqual([]);
    expect(r.none).toBe(`no answer held here for key_zzzzzzzz since ${heldSince()}`);
  });

  test("another org's answers are never shown", async () => {
    const reader = generateApiKey('organizations:beta', 'users:two', {});
    const g = minted();
    setQueryFn(async (_sql, params) => [{ id: 'api_key:rowfor', key_id: params?.key_id, scopes: ['read'], name: 'n', owner_kind: 'person' }]);
    await validateKey(g.key);
    const r = await readKeyAnswer(`ApiKey ${reader.key}`, { type: 'keyAnswer' });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.answers.filter((a) => a.key_mask12 === g.keyId.slice(0, 12))).toEqual([]);
  });

  test('a session token is refused, and a mask that is not a key id prefix is refused', async () => {
    const reader = minted();
    setQueryFn(async (_sql, params) => [{ id: 'api_key:rowfor', key_id: params?.key_id, scopes: ['read'], name: 'n', owner_kind: 'system' }]);
    const bearer = await readKeyAnswer('Bearer sometoken', { type: 'keyAnswer' });
    expect(bearer.ok).toBe(false);
    const bad = await readKeyAnswer(`ApiKey ${reader.key}`, { type: 'keyAnswer', key_mask: 'key_' + 'a'.repeat(20) });
    expect(bad.ok ? 0 : bad.status).toBe(400);
  });
});

describe('the listing and the answer name their rows', () => {
  afterEach(() => { setClassQueryFn(null); });

  test('for one row, the listed and the answered entries name the same row', async () => {
    const reader = minted();
    const g = minted();
    const table = [
      { id: 'api_key:readerrw', key_id: reader.keyId, org_id: ORG, scopes: ['read'], name: 'n', owner_kind: 'system' },
      { id: 'api_key:personrw', key_id: g.keyId, org_id: ORG, scopes: ['read'], name: 'n', owner_kind: 'person' },
    ];
    setQueryFn(async (_sql, params) => table.filter((r) => r.key_id === params?.key_id));
    setClassQueryFn(async () => table);
    await validateKey(g.key);
    const listed = await readKeyClass(`ApiKey ${reader.key}`);
    const answered = await readKeyAnswer(`ApiKey ${reader.key}`, { type: 'keyAnswer', key_mask: g.keyId.slice(0, 12) });
    expect(listed.ok && answered.ok).toBe(true);
    if (!listed.ok || !answered.ok) return;
    const entry = listed.keys.find((k) => k.key_id_mask12 === g.keyId.slice(0, 12))!;
    expect(entry.row_mask8).toBe('personrw');
    expect(answered.answers[0]).toMatchObject({ row_mask8: 'personrw', answered: 'person' });
  });

  test('MUST-FAIL: a person mark on a row validation does not read shows as a different row, answered unclassified', async () => {
    const reader = minted();
    const g = minted();
    // The listing reads a row in the org holding the person mark; validation finds another row by the key's id.
    const listedRows = [
      { id: 'api_key:readerrw', key_id: reader.keyId, org_id: ORG, scopes: ['read'], name: 'n', owner_kind: 'system' },
      { id: 'api_key:markedrw', key_id: g.keyId, org_id: ORG, scopes: ['read'], name: 'n', owner_kind: 'person' },
    ];
    setQueryFn(async (_sql, params) =>
      params?.key_id === g.keyId ? [{ id: 'api_key:unmarked', key_id: g.keyId, scopes: ['read'], name: 'n' }] : listedRows.filter((r) => r.key_id === params?.key_id));
    setClassQueryFn(async () => listedRows);
    await validateKey(g.key);
    const listed = await readKeyClass(`ApiKey ${reader.key}`);
    const answered = await readKeyAnswer(`ApiKey ${reader.key}`, { type: 'keyAnswer', key_mask: g.keyId.slice(0, 12) });
    if (!listed.ok || !answered.ok) throw new Error('read refused');
    const entry = listed.keys.find((k) => k.key_id_mask12 === g.keyId.slice(0, 12))!;
    expect(entry).toMatchObject({ owner_kind: 'person', row_mask8: 'markedrw' });
    expect(answered.answers[0]).toMatchObject({ row_mask8: 'unmarked', answered: 'unclassified' });
    expect(entry.row_mask8).not.toBe((answered.answers[0] as { row_mask8: string }).row_mask8);
  });
});

describe('bounds', () => {
  test('MUST-FAIL: a flood of mints from one key holds at most the per-key cap, newest kept, and a key answer survives', () => {
    recordKeyAnswer({ branch: 'hmac', keyId: 'key_realkeyidvalue01', orgId: ORG, foundBy: 'key_id', row: { id: 'api_key:realrow0', owner_kind: 'person' }, answered: 'person' });
    for (let i = 0; i < 10_000; i++) {
      recordOboMint({ scheme: 'api_key', keyId: 'key_floodkeyvalue001', orgId: ORG, ownerKind: 'person', node: 'n', shape: `shape${i}` });
    }
    const all = held();
    expect(all.filter((h) => h.kind === 'obo_mint').length).toBe(MINT_ANSWERS_PER_KEY);
    expect(all.filter((h) => h.kind === 'key')).toHaveLength(1);
    expect(all.find((h) => h.kind === 'key')).toMatchObject({ key_mask12: 'key_realkeyi', answered: 'person' });
    // The oldest mints were dropped, the newest kept.
    const audiences = new Set(all.filter((h) => h.kind === 'obo_mint').map((h) => (h as { audience: string }).audience));
    expect(audiences.has('n/shape9999')).toBe(true);
    expect(audiences.has('n/shape0')).toBe(false);
  });

  test('MUST-FAIL: a flood of mints from many keys holds at most the total cap, and a key answer survives', () => {
    recordKeyAnswer({ branch: 'hmac', keyId: 'key_realkeyidvalue01', orgId: ORG, foundBy: 'key_id', row: { id: 'api_key:realrow0', owner_kind: 'person' }, answered: 'person' });
    for (let i = 0; i < 10_000; i++) {
      recordOboMint({ scheme: 'api_key', keyId: `key_floodkey${String(i).padStart(8, '0')}`, orgId: ORG, ownerKind: 'person', node: 'n', shape: 's' });
    }
    const all = held();
    expect(all.filter((h) => h.kind === 'obo_mint').length).toBe(MINT_ANSWERS_HELD);
    expect(all.find((h) => h.kind === 'key')).toMatchObject({ key_mask12: 'key_realkeyi', answered: 'person' });
  });
});
