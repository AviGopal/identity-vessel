/**
 * An auth resolve posts nothing anywhere, and /health counts its outcome by reason class.
 *
 * identity used to POST an `auth_resolve_v1` telemetry trace to activity-api for every failed resolve (and a sample of
 * the successful ones), so each bad key presented to identity became a trace-store write. The resolve now only bumps an
 * in-memory count, read through identity's own /health body (`checks.auth`).
 *
 * RUN IN ITS OWN PROCESS. bun's mock.module is process-wide and outlives the file that installs it, and
 * auth-account-id.test.ts mocks ./services/trace with a pass-through that counts nothing; the same leak is why the
 * surrealdb error-log check runs in a child. So the routes are exercised in a child bun process with a fresh module
 * registry: the datastore, redis, migrations and discovery are stubbed there before index.ts loads, and fetch is a stub
 * that records every call. The child is given the old poster's key and sampling switches, so the parent commit, which
 * read them, posts on both legs; nothing in this commit reads them.
 */
import { beforeAll, describe, expect, it } from 'bun:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SRC = import.meta.dir;
const BAD_KEYS = 3;
// A child bun start under nice and a loaded host has taken ~3s; the 5s default would turn load into a false red.
const CHILD_TIMEOUT_MS = 30_000;

type Result = { fetchCalls: number; health: any; statuses: number[] };

function probe(): Result {
  const dir = mkdtempSync(join(tmpdir(), 'auth-outcomes-'));
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
        query: async () => [],
        getSurrealDB: async () => ({ query: async () => [] }),
      }));
      mock.module(${src('db/migrations.ts')}, () => ({ migrateOnStart: async () => ({}) }));
      mock.module(${src('services/discovery-client.ts')}, () => ({
        discoveryClient: null,
        registerWithDiscoveryAfterDelay: async () => {},
      }));
      test('probe', async () => {
        const { default: server } = await import(${src('index.ts')});
        const trace = await import(${src('services/trace.ts')});
        let fetchCalls = 0;
        globalThis.fetch = (async () => { fetchCalls += 1; return new Response('{}', { status: 200 }); }) as any;
        trace.resetAuthOutcomeCounts?.();
        const env = { requestIP: () => ({ address: '127.0.0.1', family: 'IPv4', port: 1 }) };
        const call = (path, init) => server.fetch(new Request('http://identity.test' + path, init), env);
        const statuses = [];
        // Success: a session JWT. Account enrichment is off in this child, so it makes no call of its own.
        const { generateToken } = await import(${src('services/jwt.ts')});
        const { token: jwt } = await generateToken({ user_id: 'users:fixture', org_id: 'organizations:fixture', role: 'member', project_ids: [], expires_in_seconds: 600 });
        statuses.push((await call('/v1/auth/resolve', { method: 'POST', headers: { Authorization: 'Bearer ' + jwt } })).status);
        for (let i = 0; i < ${BAD_KEYS}; i++) {
          statuses.push((await call('/v1/auth/resolve', { method: 'POST', headers: { Authorization: 'ApiKey mb-notakey' + i } })).status);
        }
        // The old poster was fire-and-forget: give it time to fire.
        await new Promise((r) => setTimeout(r, 200));
        const health = await (await call('/health')).json();
        process.stdout.write('RESULT ' + JSON.stringify({ fetchCalls, health, statuses }) + '\\n');
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
        // The parent commit's poster switches, set so it would post; nothing here reads them any more.
        SUBSTRATE_API_KEY: 'mb-fixturePosterKey1234567890-signatureabcdef',
        TRACE_SAMPLE_RATE: '1',
        ACTIVITY_API_ENDPOINT: 'http://127.0.0.1:9',
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

describe('auth resolve: no telemetry post, outcomes counted on /health', () => {
  let r: Result;
  beforeAll(() => {
    r = probe();
  }, CHILD_TIMEOUT_MS);

  it('control: the success leg authenticates and every bad key is refused', () => {
    expect(r.statuses).toEqual([200, ...Array(BAD_KEYS).fill(401)]);
  });

  it('MUST-FAIL: no auth resolve, success or failure, makes any fetch', () => {
    expect(r.fetchCalls).toBe(0);
  });

  it('MUST-FAIL: N bad keys read back through /health as checks.auth.invalid == N', () => {
    const auth = r.health?.checks?.auth;
    expect(auth).toBeDefined();
    expect(auth.invalid).toBe(BAD_KEYS);
    expect(auth.success).toBe(1);
    expect(auth.revoked + auth.expired + auth.unknown).toBe(0);
    expect(Number.isNaN(Date.parse(auth.since))).toBe(false);
    // Integers and a timestamp only: nothing that names a key, an org or a token.
    expect(Object.keys(auth).sort()).toEqual(['expired', 'invalid', 'revoked', 'since', 'success', 'unknown']);
  });
});
