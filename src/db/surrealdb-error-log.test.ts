/**
 * A failed query logs its parameter NAMES, never their values.
 *
 * resolveAPIKeyLegacy binds the presented API key itself as $kp, and the query
 * helper's error path used to print `[SurrealDB] Params: { kp: "<key>" }` — the
 * presented credential in the journal once per failed auth (61 lines on one fresh
 * boot). The driver is replaced by one whose query always throws, and everything the
 * helper prints is captured.
 *
 * RUN IN ITS OWN PROCESS (2026-10-07). bun's mock.module is process-wide and outlives the
 * file that installs it, and obo, login, issue-key and auth-account-id each mock this very
 * helper ('../db/surrealdb') with a query that RESOLVES. When any of them ran first (node 1's
 * file order put this file last), the import below returned their fake, the query resolved,
 * and this test failed although the helper was right. So the check runs in a child bun process
 * with a fresh module registry: the driver mock is installed there before the helper loads,
 * and no other file's mock can reach it. The second test pins that: it installs a leaking
 * helper mock in THIS process first and the check still holds.
 */
import { describe, expect, mock, test } from 'bun:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SECRET = 'mb-fixturePresentedKey1234567890-signatureabcdef';
const HELPER = join(import.meta.dir, 'surrealdb.ts');

function probe(): { rejected: boolean; out: string } {
  const dir = mkdtempSync(join(tmpdir(), 'surreal-error-log-'));
  try {
    // A TEST file run by its own `bun test`: mock.module only takes effect under the test runner.
    const p = join(dir, 'probe.test.ts');
    writeFileSync(p, `
      import { mock, test } from 'bun:test';
      mock.module('surrealdb', () => ({
        Surreal: class {
          async connect() {}
          async use() {}
          async signin() {}
          async query() { throw new Error('fixture: query failed'); }
        },
      }));
      test('probe', async () => {
        const { query } = await import(${JSON.stringify(HELPER)});
        const lines = [];
        const orig = { log: console.log, warn: console.warn, error: console.error };
        const cap = (...a) => { lines.push(a.map((x) => (typeof x === 'string' ? x : Bun.inspect(x))).join(' ')); };
        console.log = cap; console.warn = cap; console.error = cap;
        let rejected = false;
        try { await query('SELECT * FROM api_key WHERE key_prefix = $kp;', { kp: ${JSON.stringify(SECRET)} }); } catch { rejected = true; }
        Object.assign(console, orig);
        process.stdout.write('RESULT ' + JSON.stringify({ rejected, out: lines.join('\\n') }) + '\\n');
      });
    `);
    const r = Bun.spawnSync([process.execPath, 'test', p], {
      cwd: dir,
      env: { HOME: process.env.HOME ?? '', PATH: process.env.PATH ?? '', NODE_ENV: 'test', SURREALDB_URL: 'http://127.0.0.1:9' },
      stdout: 'pipe', stderr: 'pipe',
    });
    const line = r.stdout.toString().split('\n').find((l) => l.startsWith('RESULT '));
    expect(line, `probe produced no result: ${r.stderr.toString().slice(0, 400)}`).toBeDefined();
    return JSON.parse(line!.slice('RESULT '.length));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('query error logging', () => {
  test('names the parameters, never prints their values', () => {
    const r = probe();
    expect(r.rejected).toBe(true);
    expect(r.out).toContain('[SurrealDB] Params:');
    expect(r.out).toContain('kp');
    expect(r.out.includes(SECRET)).toBe(false);
  });

  test('holds when another file has mocked the helper in this process (the four that do)', () => {
    mock.module(HELPER, () => ({ query: async () => [], getDb: async () => ({}) }));
    const r = probe();
    expect(r.rejected).toBe(true);
    expect(r.out.includes(SECRET)).toBe(false);
  });
});
