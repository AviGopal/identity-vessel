/**
 * The flat /v1/auth/resolve answer (credential in the Authorization header) carries the credential's scopes.
 *
 * The nested form has always answered `scopes`; the flat form answered identity, org, account and key but not scopes, so
 * a client behind a proxy that resolves the caller's key this way could not refuse a write for a read-only key itself
 * and had to trust the next hop to. Defence in depth: the answer now carries them.
 *
 * RUN IN ITS OWN PROCESS, like auth-outcomes.test.ts: the route is exercised in a child bun process with a fresh module
 * registry, so no other file's mock.module of the datastore or redis can reach it. The datastore stub answers the key's
 * scope lookup with ['read'].
 */
import { beforeAll, describe, expect, it } from 'bun:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SRC = import.meta.dir;
// A child bun start under nice and a loaded host has taken ~3s; the 5s default would turn load into a false red.
const CHILD_TIMEOUT_MS = 30_000;

type Result = { status: number; body: any; keyId: string };

function probe(): Result {
  const dir = mkdtempSync(join(tmpdir(), 'flat-resolve-scopes-'));
  try {
    const p = join(dir, 'probe.test.ts');
    const src = (f: string) => JSON.stringify(join(SRC, f));
    writeFileSync(p, `
      import { mock, test } from 'bun:test';
      mock.module(${src('db/redis.ts')}, () => ({
        redis: {},
        isKeyRevoked: async () => false,
        revokeKey: async () => {},
        unrevokeKey: async () => {},
        getRateLimitKey: (endpoint, ip) => 'ratelimit:' + endpoint + ':' + ip,
        checkRateLimit: async () => ({ allowed: true, retryAfterSeconds: 0 }),
      }));
      mock.module(${src('db/surrealdb.ts')}, () => ({
        query: async (sql) => (/SELECT scopes FROM api_key/.test(sql) ? [{ scopes: ['read'] }] : []),
        getSurrealDB: async () => ({ query: async () => [] }),
      }));
      mock.module(${src('db/migrations.ts')}, () => ({ migrateOnStart: async () => ({}) }));
      mock.module(${src('services/discovery-client.ts')}, () => ({
        discoveryClient: null,
        registerWithDiscoveryAfterDelay: async () => {},
      }));
      test('probe', async () => {
        const { default: server } = await import(${src('index.ts')});
        const { generateApiKey } = await import(${src('services/keyGeneration.ts')});
        const { key, keyId } = generateApiKey('organizations:fixture', 'users:fixture');
        const env = { requestIP: () => ({ address: '127.0.0.1', family: 'IPv4', port: 1 }) };
        const res = await server.fetch(
          new Request('http://identity.test/v1/auth/resolve', { method: 'POST', headers: { Authorization: 'ApiKey ' + key } }),
          env,
        );
        process.stdout.write('RESULT ' + JSON.stringify({ status: res.status, body: await res.json(), keyId }) + '\\n');
      });
    `);
    const r = Bun.spawnSync([process.execPath, 'test', p], {
      cwd: dir,
      env: {
        HOME: process.env.HOME ?? '/tmp',
        PATH: process.env.PATH ?? '',
        NODE_ENV: 'test',
        ALLOW_INSECURE_API_KEY_SECRET: '1',
        USER_VESSEL_ENABLED: 'false',
        DISCOVERY_ENABLED: 'false',
      },
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const line = r.stdout.toString().split('\n').find((l) => l.startsWith('RESULT '));
    if (!line) throw new Error(`probe produced no result: ${r.stderr.toString().slice(-1500)}`);
    return JSON.parse(line.slice('RESULT '.length)) as Result;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('flat /v1/auth/resolve answer: scopes', () => {
  let r: Result;
  beforeAll(() => {
    r = probe();
  }, CHILD_TIMEOUT_MS);

  it('MUST-FAIL: the flat answer for a read-only key carries its scopes', () => {
    expect(r.status).toBe(200);
    expect(r.body.scopes).toEqual(['read']);
  });

  it('control: the rest of the flat answer is unchanged', () => {
    expect(r.body.valid).toBe(true);
    expect(r.body.user_id).toBe('users:fixture');
    expect(r.body.org_id).toBe('organizations:fixture');
    expect(r.body.account_id).toBeUndefined();
    expect(r.body.role).toBe('member');
    expect(r.body.key_id).toBe(r.keyId);
    expect(typeof r.body.jwt).toBe('string');
    expect(typeof r.body.jwt_expires_at).toBe('string');
  });
});
