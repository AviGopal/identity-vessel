/**
 * Both key routes (/v1/keys/issue, /v1/keys/generate) bind the target org/user to the caller, as /v1/jwt/generate
 * binds its claims:
 *   - org_id must be the caller's own org (403 FORBIDDEN otherwise); a missing org_id defaults to it;
 *   - user_id may differ from the caller's only for a same-org admin (a member's key); a missing one defaults to the
 *     caller's user. Identity holds no membership table, so a user of another org is covered by the org rule: the key
 *     is only ever bound to the caller's org.
 *
 * Callers modelled (every one found in the fleet's tooling must keep working):
 *   - an owner-role JWT minting for its own org (the seeder's first boot: read,write,admin and the fleet set);
 *   - a Bearer admin JWT for its own org/user (substrate-key.sh issue);
 *   - an ApiKey with scope admin for its own org/user (the seeder's corpus runner key);
 *   - the dashboard's owner JWT, own org/user, read,write.
 *
 * RUN IN ITS OWN PROCESS, like key-name.test.ts: the routes are exercised in a child bun process with a fresh module
 * registry, so no other file's mock.module of the datastore or redis can reach it.
 */
import { beforeAll, describe, expect, it } from 'bun:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SRC = import.meta.dir;
// A child bun start under nice and a loaded host has taken ~3s; the 5s default would turn load into a false red.
const CHILD_TIMEOUT_MS = 30_000;

// No '-' in any id: the key payload is dash-separated ({org}-{user}-{keyId}-{iss}).
const ORG_A = 'organizations:alpha';
const ORG_B = 'organizations:bravo';
const OWNER = 'users:ownera';
const OPERATOR = 'users:operatora';
const MEMBER = 'users:membera';
const B_USER = 'users:memberb';

type Answer = { status: number; body: any; minted?: { orgId?: string; userId?: string } | null };
type Result = { answers: Record<string, Answer>; creates: Record<string, any[]> };

const ROUTES = ['/v1/keys/issue', '/v1/keys/generate'] as const;

function probe(): Result {
  const dir = mkdtempSync(join(tmpdir(), 'key-target-binding-'));
  try {
    const p = join(dir, 'probe.test.ts');
    const src = (f: string) => JSON.stringify(join(SRC, f));
    writeFileSync(p, `
      import { mock, test } from 'bun:test';
      const rows = {};
      let creates = [];
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
          if (/CREATE api_key/.test(sql)) {
            creates.push({ org_id: params?.org_id, user_id: params?.user_id, scopes: params?.scopes });
            rows[params.key_id] = { scopes: params.scopes };
            return [];
          }
          if (/FROM api_key WHERE key_id = \\$key_id/.test(sql) && rows[params?.key_id]) return [rows[params.key_id]];
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
        const { validateKey } = await import(${src('services/validation.ts')});
        const A = ${JSON.stringify(ORG_A)}, B = ${JSON.stringify(ORG_B)};
        const OWNER = ${JSON.stringify(OWNER)}, OPERATOR = ${JSON.stringify(OPERATOR)};
        const MEMBER = ${JSON.stringify(MEMBER)}, B_USER = ${JSON.stringify(B_USER)};

        // An owner-role token, as login answers, for the caller's own org.
        const owner = 'Bearer ' + (await generateToken({ user_id: OWNER, org_id: A, role: 'owner' })).token;
        // substrate-key.sh: an admin-role JWT for the operator's own org/user.
        const adminJwt = 'Bearer ' + (await generateToken({ user_id: OPERATOR, org_id: A, role: 'admin' })).token;
        // SUBSTRATE_ADMIN_KEY: an ApiKey whose row carries scope admin.
        const ak = generateApiKey(A, OPERATOR);
        rows[ak.keyId] = { scopes: ['read', 'write', 'admin'] };
        const adminKey = 'ApiKey ' + ak.key;
        // A read/write key: not admin, refused before any binding.
        const rw = generateApiKey(A, OPERATOR);
        rows[rw.keyId] = { scopes: ['read', 'write'] };
        const rwKey = 'ApiKey ' + rw.key;

        const env = { requestIP: () => ({ address: '127.0.0.1', family: 'IPv4', port: 1 }) };
        const call = async (path, auth, body) => {
          const res = await server.fetch(new Request('http://identity.test' + path, {
            method: 'POST',
            headers: { 'content-type': 'application/json', Authorization: auth },
            body: JSON.stringify(body),
          }), env);
          const json = await res.json();
          const key = json?.data?.key;
          let minted = null;
          if (typeof key === 'string') {
            const v = await validateKey(key);
            minted = { orgId: v.orgId, userId: v.userId };
          }
          return { status: res.status, body: { ...json, data: json?.data ? { ...json.data, key: key ? '<redacted>' : undefined, metadata: undefined } : json?.data }, minted };
        };

        const cases = {
          crossOrgOwner: [owner, { org_id: B, user_id: OWNER, scopes: ['read', 'write'] }],
          crossOrgForeignUser: [owner, { org_id: B, user_id: B_USER, scopes: ['read', 'write'] }],
          crossOrgAdminKey: [adminKey, { org_id: B, user_id: B_USER, scopes: ['read', 'write', 'admin'] }],
          crossOrgAdminScope: [owner, { org_id: B, user_id: B_USER, scopes: ['read', 'write', 'admin'] }],
          foreignUserNoOrg: [owner, { user_id: B_USER, scopes: ['read'] }],
          ownSelf: [owner, { org_id: A, user_id: OWNER, scopes: ['read', 'write'] }],
          seederAdmin: [owner, { org_id: A, user_id: OWNER, scopes: ['read', 'write', 'admin'], name: 'substrate-admin' }],
          seederFleet: [owner, { org_id: A, user_id: OWNER, scopes: ['read', 'write', 'db:admin', 'templates:admin'], name: 'substrate-default' }],
          substrateKeySh: [adminJwt, { org_id: A, user_id: OPERATOR, scopes: ['read', 'write', 'admin'], name: 'cli' }],
          corpusRunner: [adminKey, { org_id: A, user_id: OPERATOR, scopes: ['verdict-corpus:write'], name: 'corpus-runner' }],
          sameOrgMember: [owner, { org_id: A, user_id: MEMBER, scopes: ['read'] }],
          defaults: [adminJwt, { scopes: ['read'] }],
          nonAdmin: [rwKey, { org_id: A, user_id: OPERATOR }],
        };
        const answers = {};
        const createsBy = {};
        for (const route of ${JSON.stringify(ROUTES)}) {
          for (const [name, [auth, body]] of Object.entries(cases)) {
            creates = [];
            answers[route + ' ' + name] = await call(route, auth, body);
            createsBy[route + ' ' + name] = creates;
          }
        }
        // /v1/jwt/generate: its own binding, unchanged by this commit.
        answers['jwt crossOrg'] = await call('/v1/jwt/generate', adminKey, { org_id: B, user_id: OPERATOR, role: 'member' });
        answers['jwt own'] = await call('/v1/jwt/generate', adminKey, { org_id: A, user_id: OPERATOR, role: 'member' });
        answers['jwt otherUser'] = await call('/v1/jwt/generate', adminKey, { org_id: A, user_id: MEMBER, role: 'member' });
        process.stdout.write('RESULT ' + JSON.stringify({ answers, creates: createsBy }) + '\\n');
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
    const line = stdout.split('\n').find((l) => l.startsWith('RESULT '));
    if (!line) throw new Error(`probe produced no result: ${r.stderr.toString().slice(-1500)}`);
    return JSON.parse(line.slice('RESULT '.length)) as Result;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const FORBIDDEN = { code: 'FORBIDDEN', message: 'Key org_id must match the authenticated credential' };

describe('/v1/keys/issue and /v1/keys/generate: the key target is bound to the caller', () => {
  let r: Result;
  beforeAll(() => {
    r = probe();
  }, CHILD_TIMEOUT_MS);

  const refused = (a: Answer) => {
    expect(a.status).toBe(403);
    expect(a.body.success).toBe(false);
    expect(a.body.error).toEqual(FORBIDDEN);
    expect(a.minted).toBeNull();
  };
  const issuedFor = (a: Answer, orgId: string, userId: string) => {
    expect(a.status).toBe(200);
    expect(a.body.success).toBe(true);
    expect(a.minted).toEqual({ orgId, userId });
  };

  for (const route of ROUTES) {
    const at = (name: string) => r.answers[`${route} ${name}`];
    const writes = (name: string) => r.creates[`${route} ${name}`];

    it(`MUST-FAIL ${route}: refuses a key for another org, and writes no key`, () => {
      refused(at('crossOrgOwner'));
      expect(writes('crossOrgOwner')).toEqual([]);
    });

    it(`MUST-FAIL ${route}: refuses a key for another org's user, and writes no key`, () => {
      refused(at('crossOrgForeignUser'));
      refused(at('crossOrgAdminScope'));
      expect(writes('crossOrgForeignUser')).toEqual([]);
      expect(writes('crossOrgAdminScope')).toEqual([]);
    });

    it(`MUST-FAIL ${route}: refuses another org for an admin-scoped ApiKey caller too`, () => {
      refused(at('crossOrgAdminKey'));
      expect(writes('crossOrgAdminKey')).toEqual([]);
    });

    it(`MUST-FAIL ${route}: a foreign user with no org_id is bound to the caller's org, never the user's`, () => {
      issuedFor(at('foreignUserNoOrg'), ORG_A, B_USER);
    });

    it(`MUST-FAIL ${route}: a missing org_id and user_id default to the caller's own`, () => {
      issuedFor(at('defaults'), ORG_A, OPERATOR);
    });

    it(`control ${route}: same-org, same-user issue (the dashboard) answers a key in the caller's org`, () => {
      issuedFor(at('ownSelf'), ORG_A, OWNER);
    });

    it(`control ${route}: the seeder's owner JWT mints read,write,admin and the fleet scope set for its own org`, () => {
      issuedFor(at('seederAdmin'), ORG_A, OWNER);
      issuedFor(at('seederFleet'), ORG_A, OWNER);
    });

    it(`control ${route}: substrate-key.sh (Bearer admin JWT, own org/user) mints`, () => {
      issuedFor(at('substrateKeySh'), ORG_A, OPERATOR);
    });

    it(`control ${route}: the ApiKey admin own-org path (corpus runner) mints`, () => {
      issuedFor(at('corpusRunner'), ORG_A, OPERATOR);
    });

    it(`control ${route}: a same-org admin issues for a member of its org`, () => {
      issuedFor(at('sameOrgMember'), ORG_A, MEMBER);
    });

    it(`control ${route}: a non-admin key is still refused before any binding`, () => {
      const a = at('nonAdmin');
      expect(a.status).toBe(403);
      expect(a.body.error.code).toBe('FORBIDDEN');
      expect(a.body.error.message).toBe('API key does not have admin scope');
      expect(a.minted).toBeNull();
    });
  }

  it('control /v1/keys/issue: an accepted mint writes exactly one row, in the caller\'s org', () => {
    expect(r.creates['/v1/keys/issue seederAdmin']).toEqual([{ org_id: ORG_A, user_id: OWNER, scopes: ['read', 'write', 'admin'] }]);
    expect(r.creates['/v1/keys/issue corpusRunner']).toEqual([{ org_id: ORG_A, user_id: OPERATOR, scopes: ['verdict-corpus:write'] }]);
  });

  it('control /v1/jwt/generate: its caller binding is unchanged', () => {
    expect(r.answers['jwt crossOrg'].status).toBe(403);
    expect(r.answers['jwt crossOrg'].body.error).toEqual({ code: 'FORBIDDEN', message: 'Token claims must match the authenticated credential' });
    expect(r.answers['jwt otherUser'].status).toBe(403);
    expect(r.answers['jwt own'].status).toBe(200);
    expect(r.answers['jwt own'].body.success).toBe(true);
  });
});
