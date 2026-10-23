/**
 * /v1/keys/validate and /v1/auth/resolve answer the validated key's `name`, so a consumer can attribute a write by it.
 *
 * Both answered key_id, org, role, scopes and user id but not the key's human-readable name, so authorship by key name
 * was unmeasurable anywhere downstream. The name comes from the same api_key row read that already supplies the scopes;
 * an unnamed key answers `name: null`; an invalid key is refused exactly as before, with no name.
 *
 * RUN IN ITS OWN PROCESS, like flat-resolve-scopes.test.ts: the routes are exercised in a child bun process with a
 * fresh module registry, so no other file's mock.module of the datastore or redis can reach it. The child writes the
 * fixture key values to a file (never to stdout), so the parent can check they appear in no answer and no log line.
 */
import { beforeAll, describe, expect, it } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SRC = import.meta.dir;
// A child bun start under nice and a loaded host has taken ~3s; the 5s default would turn load into a false red.
const CHILD_TIMEOUT_MS = 30_000;
const NAME = 'fixture-laptop-key';

type Answer = { status: number; body: any };
type Result = {
  ids: { named: string; unnamed: string };
  validate: { named: Answer; unnamed: Answer; invalid: Answer };
  nested: { named: Answer; invalid: Answer };
  flat: { named: Answer; unnamed: Answer; invalid: Answer };
  keys: string[];
  output: string;
};

function probe(): Result {
  const dir = mkdtempSync(join(tmpdir(), 'key-name-'));
  try {
    const p = join(dir, 'probe.test.ts');
    const keysFile = join(dir, 'keys.json');
    const src = (f: string) => JSON.stringify(join(SRC, f));
    writeFileSync(p, `
      import { mock, test } from 'bun:test';
      import { writeFileSync } from 'node:fs';
      const rows = {};
      mock.module(${src('db/redis.ts')}, () => ({
        redis: {},
        isKeyRevoked: async () => false,
        revokeKey: async () => {},
        unrevokeKey: async () => {},
        getRateLimitKey: (endpoint, ip) => 'ratelimit:' + endpoint + ':' + ip,
        checkRateLimit: async () => ({ allowed: true, retryAfterSeconds: 0 }),
      }));
      mock.module(${src('db/surrealdb.ts')}, () => ({
        query: async (sql, params) => (/FROM api_key WHERE key_id = \\$key_id/.test(sql) && rows[params?.key_id] ? [rows[params.key_id]] : []),
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
        const named = generateApiKey('organizations:fixture', 'users:fixture');
        const unnamed = generateApiKey('organizations:fixture', 'users:fixture');
        rows[named.keyId] = { scopes: ['read', 'write'], name: ${JSON.stringify(NAME)} };
        rows[unnamed.keyId] = { scopes: ['read', 'write'] };
        // Same payload, wrong signature: format-valid, HMAC-invalid.
        const invalid = named.key.slice(0, -4) + (named.key.endsWith('0000') ? '1111' : '0000');
        writeFileSync(${JSON.stringify(keysFile)}, JSON.stringify([named.key, unnamed.key, invalid]));
        const env = { requestIP: () => ({ address: '127.0.0.1', family: 'IPv4', port: 1 }) };
        const call = async (path, init) => {
          const res = await server.fetch(new Request('http://identity.test' + path, { method: 'POST', ...init }), env);
          return { status: res.status, body: await res.json() };
        };
        const json = { 'content-type': 'application/json' };
        const validate = (k) => call('/v1/keys/validate', { headers: json, body: JSON.stringify({ api_key: k }) });
        const nested = (k) => call('/v1/auth/resolve', {
          headers: json,
          body: JSON.stringify({ impulse: { type: 'authentication', pointer: { type: 'apiKey', apiKey: k } } }),
        });
        const flat = (k) => call('/v1/auth/resolve', { headers: { Authorization: 'ApiKey ' + k } });
        const out = {
          ids: { named: named.keyId, unnamed: unnamed.keyId },
          validate: { named: await validate(named.key), unnamed: await validate(unnamed.key), invalid: await validate(invalid) },
          nested: { named: await nested(named.key), invalid: await nested(invalid) },
          flat: { named: await flat(named.key), unnamed: await flat(unnamed.key), invalid: await flat(invalid) },
        };
        process.stdout.write('RESULT ' + JSON.stringify(out) + '\\n');
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
    const stdout = r.stdout.toString();
    const stderr = r.stderr.toString();
    const line = stdout.split('\n').find((l) => l.startsWith('RESULT '));
    if (!line) throw new Error(`probe produced no result: ${stderr.slice(-1500)}`);
    const keys = JSON.parse(readFileSync(keysFile, 'utf8')) as string[];
    return { ...JSON.parse(line.slice('RESULT '.length)), keys, output: stdout + '\n' + stderr } as Result;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('/v1/keys/validate and /v1/auth/resolve: the key name', () => {
  let r: Result;
  beforeAll(() => {
    r = probe();
  }, CHILD_TIMEOUT_MS);

  it('MUST-FAIL: /v1/keys/validate answers a named key with its name', () => {
    expect(r.validate.named.status).toBe(200);
    expect(r.validate.named.body.data.valid).toBe(true);
    expect(r.validate.named.body.data.key_id).toBe(r.ids.named);
    expect(r.validate.named.body.data.name).toBe(NAME);
  });

  it('MUST-FAIL: /v1/auth/resolve answers a named key with its name, nested and flat', () => {
    expect(r.nested.named.status).toBe(200);
    expect(r.nested.named.body.data.keyId).toBe(r.ids.named);
    expect(r.nested.named.body.data.name).toBe(NAME);
    expect(r.flat.named.status).toBe(200);
    expect(r.flat.named.body.key_id).toBe(r.ids.named);
    expect(r.flat.named.body.name).toBe(NAME);
  });

  it('an unnamed key answers name: null', () => {
    expect(r.validate.unnamed.body.data.valid).toBe(true);
    expect(r.validate.unnamed.body.data).toHaveProperty('name', null);
    expect(r.flat.unnamed.status).toBe(200);
    expect(r.flat.unnamed.body).toHaveProperty('name', null);
  });

  it('control: an invalid key is refused exactly as before, with no name', () => {
    expect(r.validate.invalid).toEqual({
      status: 200,
      body: { success: true, data: { valid: false, error: 'Invalid API key signature' } },
    });
    expect(r.nested.invalid).toEqual({
      status: 401,
      body: { success: false, error: { code: 'AUTHENTICATION_FAILED', message: 'Invalid API key signature' } },
    });
    expect(r.flat.invalid).toEqual({ status: 401, body: { valid: false, error: 'Invalid API key signature' } });
  });

  it('control: no key value appears in any answer or log line', () => {
    expect(r.keys).toHaveLength(3);
    const answers = JSON.stringify({ v: r.validate, n: r.nested, f: r.flat });
    for (const k of r.keys) {
      expect(answers.includes(k)).toBe(false);
      expect(r.output.includes(k)).toBe(false);
    }
  });
});
