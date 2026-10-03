/**
 * A failed query logs its parameter NAMES, never their values.
 *
 * resolveAPIKeyLegacy binds the presented API key itself as $kp, and the query
 * helper's error path used to print `[SurrealDB] Params: { kp: "<key>" }` — the
 * presented credential in the journal once per failed auth (61 lines on one fresh
 * boot). The driver is replaced by one whose query always throws, and everything the
 * helper prints is captured.
 */
import { afterAll, beforeAll, describe, expect, mock, test } from 'bun:test';

mock.module('surrealdb', () => ({
  Surreal: class {
    async connect() {}
    async use() {}
    async signin() {}
    async query() { throw new Error('fixture: query failed'); }
  },
}));

const { query } = await import('./surrealdb');

const SECRET = 'mb-fixturePresentedKey1234567890-signatureabcdef';
const lines: string[] = [];
const orig = { log: console.log, warn: console.warn, error: console.error };

beforeAll(() => {
  const cap = (...a: unknown[]) => { lines.push(a.map((x) => (typeof x === 'string' ? x : Bun.inspect(x))).join(' ')); };
  console.log = cap; console.warn = cap; console.error = cap;
});
afterAll(() => { Object.assign(console, orig); });

describe('query error logging', () => {
  test('names the parameters, never prints their values', async () => {
    await expect(query('SELECT * FROM api_key WHERE key_prefix = $kp;', { kp: SECRET })).rejects.toThrow();
    const out = lines.join('\n');
    expect(out).toContain('[SurrealDB] Params:');
    expect(out).toContain('kp');
    expect(out.includes(SECRET)).toBe(false);
  });
});
