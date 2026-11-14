/**
 * The apiKeyClass impulse on identity's resolve door: a service ApiKey caller reads each of
 * its org's keys by a 12-character id mask with owner_kind, owner_node and is_admin, and
 * nothing else; a session (Bearer) caller is refused.
 *
 * MUST-FAIL on a tree without the resolver: the door then answers the impulse as a malformed
 * authentication impulse (400), so the service caller's read below is red by assertion.
 *
 * RUN IN ITS OWN PROCESS, like flat-resolve-scopes.test.ts: the route is exercised in a child
 * bun process with a fresh module registry. Every key id, hash and name below is a synthetic
 * fixture; the caller's key is generated in the child under the test-only default secret.
 */
import { describe, expect, it } from 'bun:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SRC = import.meta.dir;
const CHILD_TIMEOUT_MS = 30_000;
const ORG = 'organizations:fixtureorg';

// Rows as the api_key table holds them, every field a real row carries (key_hash included),
// so "nothing beyond the four fields" is checked against what the read could leak.
const ROWS = [
  { key_id: 'key_FIXTUREsys000000A', key_hash: 'f'.repeat(64), name: 'goal-host-vessel', scopes: ['read', 'write', 'tools-exec'], prefix: 'mb-fixture', user_id: 'users:fixture', org_id: ORG },
  { key_id: 'key_FIXTUREadm000000B', key_hash: 'e'.repeat(64), name: 'substrate-admin', scopes: ['read', 'write', 'admin'], prefix: 'mb-fixture', user_id: 'users:fixture', org_id: ORG },
  { key_id: 'key_FIXTUREfree00000C', key_hash: 'd'.repeat(64), name: 'fixture-free-form-name', scopes: ['read'], prefix: 'mb-fixture', user_id: 'users:fixture', org_id: ORG },
  { key_id: 'key_FIXTUREop0000000D', key_hash: 'c'.repeat(64), name: 'fixture-person-key', scopes: ['read'], owner_kind: 'operator', prefix: 'mb-fixture', user_id: 'users:fixture', org_id: ORG },
  { key_id: 'key_FIXTUREpeer0000E', key_hash: 'a'.repeat(64), name: 'fixture-join-key', scopes: ['read', 'write'], owner_kind: 'peer', owner_node: 'node-a', prefix: 'mb-fixture', user_id: 'users:fixture', org_id: ORG },
  { key_hash: 'b'.repeat(64), name: 'concept-db', scopes: ['read'], org_id: ORG },
];

type Result = { status: number; body: any; reads: Array<{ sql: string; params: any }> };

function probe(auth: 'service' | 'bearer' | 'invalid'): Result {
  const dir = mkdtempSync(join(tmpdir(), 'key-class-door-'));
  try {
    const p = join(dir, 'probe.test.ts');
    const src = (f: string) => JSON.stringify(join(SRC, f));
    writeFileSync(p, `
      import { mock, test } from 'bun:test';
      const reads = [];
      mock.module(${src('db/redis.ts')}, () => ({
        redis: {},
        isKeyRevoked: async () => false,
        revokeKey: async () => {},
        unrevokeKey: async () => {},
        getRateLimitKey: (endpoint, ip) => 'ratelimit:' + endpoint + ':' + ip,
        checkRateLimit: async () => ({ allowed: true, retryAfterSeconds: 0 }),
      }));
      mock.module(${src('db/surrealdb.ts')}, () => ({
        query: async (sql, params) => {
          if (/SELECT scopes, name(, owner_kind)? FROM api_key/.test(sql)) return [{ scopes: ['read', 'write'] }];
          if (/FROM api_key WHERE org_id/.test(sql)) { reads.push({ sql, params }); return ${JSON.stringify(ROWS)}; }
          return [];
        },
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
        const { generateToken } = await import(${src('services/jwt.ts')});
        const { key } = generateApiKey(${JSON.stringify(ORG)}, 'users:fixture');
        const header = ${JSON.stringify(auth)} === 'service' ? 'ApiKey ' + key
          : ${JSON.stringify(auth)} === 'bearer'
            ? 'Bearer ' + (await generateToken({ user_id: 'users:fixture', org_id: ${JSON.stringify(ORG)}, role: 'admin', project_ids: [], expires_in_seconds: 600 })).token
            : 'ApiKey mb-not-a-valid-fixture-key';
        const env = { requestIP: () => ({ address: '127.0.0.1', family: 'IPv4', port: 1 }) };
        const res = await server.fetch(
          new Request('http://identity.test/v1/auth/resolve', {
            method: 'POST',
            headers: { Authorization: header, 'Content-Type': 'application/json' },
            body: JSON.stringify({ impulse: { pointer: { type: 'apiKeyClass' } } }),
          }),
          env,
        );
        process.stdout.write('RESULT ' + JSON.stringify({ status: res.status, body: await res.json(), reads }) + '\\n');
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
        SUBSTRATE_NAME: 'fixture-node',
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

describe('apiKeyClass on the resolve door', () => {
  it('a service ApiKey caller reads its org\'s keys: a 12-character mask, owner_kind, owner_node, is_admin', () => {
    const r = probe('service');
    expect(r.status).toBe(200);
    expect(r.body.success).toBe(true);
    const keys = r.body.data.keys as Array<Record<string, unknown>>;
    expect(keys).toEqual([
      { key_id_mask12: 'key_FIXTUREs', row_mask8: '-', owner_kind: 'system', owner_node: 'fixture-node', is_admin: false },
      { key_id_mask12: 'key_FIXTUREa', row_mask8: '-', owner_kind: 'unclassified', owner_node: null, is_admin: true },
      { key_id_mask12: 'key_FIXTUREf', row_mask8: '-', owner_kind: 'unclassified', owner_node: null, is_admin: false },
      { key_id_mask12: 'key_FIXTUREo', row_mask8: '-', owner_kind: 'operator', owner_node: null, is_admin: false },
      { key_id_mask12: 'key_FIXTUREp', row_mask8: '-', owner_kind: 'peer', owner_node: 'node-a', is_admin: false },
    ]);
    for (const k of keys) {
      expect(Object.keys(k).sort()).toEqual(['is_admin', 'key_id_mask12', 'owner_kind', 'owner_node', 'row_mask8']);
      expect((k.key_id_mask12 as string).length).toBe(12);
    }
    // The read is the caller's org only, and never selects the hash.
    expect(r.reads.length).toBe(1);
    expect(r.reads[0]!.params).toEqual({ org_id: ORG });
    expect(r.reads[0]!.sql).not.toContain('key_hash');
  }, CHILD_TIMEOUT_MS);

  it('no response field carries more than the mask: full ids, hashes, names and scopes are absent', () => {
    const text = JSON.stringify(probe('service').body);
    for (const row of ROWS) {
      if (row.key_id) expect(text).not.toContain(row.key_id);
      expect(text).not.toContain(row.key_hash);
      expect(text).not.toContain(row.name);
    }
    expect(text).not.toContain('tools-exec');
    expect(text).not.toContain('mb-');
  }, CHILD_TIMEOUT_MS);

  it('a session (Bearer) caller is refused, even an admin one, and nothing is read', () => {
    const r = probe('bearer');
    expect(r.status).toBe(403);
    expect(r.body.success).toBe(false);
    expect(r.body.data).toBeUndefined();
    expect(r.reads.length).toBe(0);
  }, CHILD_TIMEOUT_MS);

  it('an ApiKey that does not validate is refused, and nothing is read', () => {
    const r = probe('invalid');
    expect(r.status).toBe(401);
    expect(r.body.success).toBe(false);
    expect(r.reads.length).toBe(0);
  }, CHILD_TIMEOUT_MS);
});
