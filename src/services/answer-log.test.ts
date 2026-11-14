/**
 * Each key answer is said in one line naming its branch, how its row was found, the row, the stored class and the class
 * answered, once per key while the answer stays the same. The line never holds a key or a key_prefix value.
 * The HMAC branch runs through validateKey with a real minted key and the query stubbed; the legacy branch through the
 * auth resolver with the database module stubbed, as the other auth tests do.
 */
import { test, expect, describe, beforeEach, afterEach, mock, spyOn } from 'bun:test';

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
import { __resetAnswerLogForTests, logOboMint } from './answer-log';

const PLANTED_PREFIX = 'plantedprefixvaluethatmustneverprint';
let lines: string[] = [];
let spy: ReturnType<typeof spyOn>;

beforeEach(() => {
  __resetAnswerLogForTests();
  lines = [];
  spy = spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });
});
afterEach(() => { spy.mockRestore(); setQueryFn(null); legacyRows = []; });

const answers = () => lines.filter((l) => l.startsWith('[KeyAnswer]'));
const minted = () => generateApiKey('organizations:alpha', 'users:one', {});

describe('hmac branch', () => {
  test('a row found by key_id: its class, the row, and how it was found', async () => {
    const g = minted();
    setQueryFn(async () => [{ id: 'api_key:recordone', key_id: g.keyId, key_prefix: PLANTED_PREFIX, scopes: ['read'], name: 'n', owner_kind: 'person' }]);
    const v = await validateKey(g.key);
    expect(v.ownerKind).toBe('person');
    expect(answers()).toEqual([`[KeyAnswer] branch=hmac key=${g.keyId.slice(0, 12)} found_by=key_id row=recordon owner_kind=person answered=person`]);
  });

  test('a row found by its record id, its key_id empty', async () => {
    const g = minted();
    setQueryFn(async () => [{ id: `api_key:${g.keyId}`, scopes: ['read'], name: 'n', owner_kind: 'operator' }]);
    await validateKey(g.key);
    expect(answers()[0]).toContain('found_by=record_id');
    expect(answers()[0]).toContain('answered=operator');
  });

  test('a row found by neither key_id nor record id was found by key_prefix', async () => {
    const g = minted();
    setQueryFn(async () => [{ id: 'api_key:otherrow', key_id: 'key_someotherkeyid', scopes: ['read'], name: 'n' }]);
    await validateKey(g.key);
    expect(answers()[0]).toContain('found_by=key_prefix row=otherrow owner_kind=none answered=unclassified');
  });

  test('a stored owner_kind that is not a class reads "invalid", and the class answered is derived', async () => {
    const g = minted();
    setQueryFn(async () => [{ id: 'api_key:recordone', key_id: g.keyId, scopes: ['read'], name: 'n', owner_kind: 'Person' }]);
    await validateKey(g.key);
    expect(answers()[0]).toContain('owner_kind=invalid answered=unclassified');
  });

  test('no row, two rows, and a failed read are each said', async () => {
    const g = minted();
    setQueryFn(async () => []);
    await validateKey(g.key);
    expect(answers().at(-1)).toContain('found_by=none row=- owner_kind=- answered=none');
    __resetAnswerLogForTests();
    setQueryFn(async () => [{ id: 'api_key:a', key_id: g.keyId }, { id: 'api_key:b', key_prefix: g.keyId }]);
    await validateKey(g.key);
    expect(answers().at(-1)).toContain('found_by=ambiguous');
    __resetAnswerLogForTests();
    setQueryFn(async () => { throw new Error('down'); });
    await validateKey(g.key);
    expect(answers().at(-1)).toContain('found_by=error');
  });

  test('the same answer is said once; a changed answer is said again', async () => {
    const g = minted();
    let kind = 'person';
    setQueryFn(async () => [{ id: 'api_key:recordone', key_id: g.keyId, scopes: ['read'], name: 'n', owner_kind: kind }]);
    await validateKey(g.key);
    await validateKey(g.key);
    expect(answers()).toHaveLength(1);
    kind = 'operator';
    await validateKey(g.key);
    expect(answers()).toHaveLength(2);
    expect(answers()[1]).toContain('answered=operator');
  });

  test('the selected fields never include key_prefix, and no line holds a key or a key_prefix value', async () => {
    const g = minted();
    let sql = '';
    setQueryFn(async (s) => { sql = s; return [{ id: 'api_key:recordone', key_id: g.keyId, key_prefix: PLANTED_PREFIX, scopes: ['read'], owner_kind: 'person' }]; });
    await validateKey(g.key);
    expect(sql.split(' FROM ')[0]).not.toContain('key_prefix');
    for (const l of lines) {
      expect(l).not.toContain(PLANTED_PREFIX);
      expect(l).not.toContain(g.key);
    }
  });
});

describe('legacy branch', () => {
  const oldKey = 'oldformatkeyfixturevalue';

  test('a row found by its stored prefix: named by its stable id, never by the presented value', async () => {
    legacyRows = [{ id: 'api_key:legacyrow', key_id: 'key_legacykeyidvalue', org_id: 'organizations:alpha', user_id: 'users:one', scopes: ['read'], name: 'n', is_active: true }];
    const r = await resolveAuthentication({ type: 'authentication', pointer: { type: 'apiKey', apiKey: oldKey } } as any);
    expect(r.authenticated).toBe(true);
    expect(answers()).toEqual(['[KeyAnswer] branch=legacy key=key_legacyke found_by=key_prefix row=legacyro owner_kind=none answered=unclassified']);
    for (const l of lines) expect(l).not.toContain(oldKey);
  });

  test('no row, an inactive row and a failed read are each said', async () => {
    legacyRows = [];
    await resolveAuthentication({ type: 'authentication', pointer: { type: 'apiKey', apiKey: oldKey } } as any);
    expect(answers().at(-1)).toBe('[KeyAnswer] branch=legacy key=- found_by=none row=- owner_kind=- answered=none');
    legacyRows = [{ id: 'api_key:legacyrow', key_id: 'key_legacykeyidvalue', is_active: false, owner_kind: 'person' }];
    await resolveAuthentication({ type: 'authentication', pointer: { type: 'apiKey', apiKey: oldKey } } as any);
    expect(answers().at(-1)).toContain('answered=inactive');
    legacyRows = new Error('down');
    await resolveAuthentication({ type: 'authentication', pointer: { type: 'apiKey', apiKey: oldKey } } as any);
    expect(answers().at(-1)).toContain('branch=legacy key=- found_by=error');
    for (const l of lines) expect(l).not.toContain(oldKey);
  });
});

describe('on-behalf-of mint', () => {
  test('the class a token carries is said once per caller and audience', () => {
    logOboMint({ scheme: 'api_key', keyId: 'key_callerkeyidvalue', ownerKind: 'person', node: 'nodeA', shape: 'record_write' });
    logOboMint({ scheme: 'api_key', keyId: 'key_callerkeyidvalue', ownerKind: 'person', node: 'nodeA', shape: 'record_write' });
    logOboMint({ scheme: 'session', keyId: undefined, ownerKind: undefined, node: 'nodeA', shape: 'record_write' });
    expect(lines.filter((l) => l.startsWith('[OboMint]'))).toEqual([
      '[OboMint] caller=api_key key=key_callerke carries=person audience=nodeA/record_write',
      '[OboMint] caller=session key=- carries=none audience=nodeA/record_write',
    ]);
  });
});
