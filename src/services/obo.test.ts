/**
 * On-behalf-of tokens: the federation ingress hands a local vessel a token that
 * names the CALLER and is bound to one node and one shape.
 *
 * Each test is a falsifier for one property the qa ruling requires:
 *   - the token carries the caller's identity, not the ingress's;
 *   - it cannot be re-delegated (presented again as a caller credential);
 *   - a validator stating its audience refuses it for another node or shape;
 *   - privileged routes (JWT mint, admin) refuse it;
 *   - it carries no database access claims and expires within the cap.
 */
import { test, expect, describe, mock } from 'bun:test';

mock.module('../db/redis', () => ({
  redis: {},
  isKeyRevoked: async () => false,
  revokeKey: async () => {},
  unrevokeKey: async () => {},
  getRateLimitKey: (endpoint: string, ip: string) => `ratelimit:${endpoint}:${ip}`,
  checkRateLimit: async () => ({ allowed: true, retryAfterSeconds: 0 }),
}));
mock.module('../db/surrealdb', () => ({
  query: async () => [],
  getSurrealDB: async () => { throw new Error('SurrealDB stubbed in obo test'); },
}));

import { decode, sign } from 'hono/jwt';
import { mintOnBehalfOf, MAX_TTL_SECONDS } from './obo';
import { generateApiKey } from './keyGeneration';
import { verifyToken } from './jwt';
import { authorizeAdmin } from '../resolvers/issue-key';
import { resolveAuthentication } from '../resolvers/auth';

const actor = generateApiKey('metabob', 'users:transport', {}).key;
const caller = generateApiKey('metabob', 'users:caller', {}).key;
const callerKeyId = (() => {
  const payload = Buffer.from(caller.slice(3, caller.lastIndexOf('-')), 'base64url').toString('utf-8');
  return payload.split('-')[2];
})();

async function mint(node = 'node-a', shape = 'fixtureRead') {
  const r = await mintOnBehalfOf(`ApiKey ${actor}`, `ApiKey ${caller}`, { node, shape });
  if (!r.ok) throw new Error(`mint failed: ${r.code}`);
  return r;
}

describe('mintOnBehalfOf', () => {
  test('the token names the caller, not the ingress that obtained it', async () => {
    const r = await mint();
    const { payload } = decode(r.token) as any;
    expect(payload.user_id).toBe('users:caller');
    expect(payload.caller_key_id).toBe(callerKeyId);
    expect(payload.act.sub).toBe('users:transport');
    expect(payload.aud).toBe('substrate:node-a');
    expect(payload.obo_shape).toBe('fixtureRead');
    expect(payload.typ).toBe('obo');
  });

  test('it is not a database credential and expires within the cap', async () => {
    const r = await mintOnBehalfOf(`ApiKey ${actor}`, `ApiKey ${caller}`, { node: 'n', shape: 's' }, 99999);
    if (!r.ok) throw new Error(r.code);
    const { payload } = decode(r.token) as any;
    expect(payload.AC).toBeUndefined();
    expect(payload.NS).toBeUndefined();
    expect(payload.exp - payload.iat).toBeLessThanOrEqual(MAX_TTL_SECONDS);
  });

  test('an OBO token presented again as a caller credential is refused (no re-delegation)', async () => {
    const r = await mint();
    const again = await mintOnBehalfOf(`ApiKey ${actor}`, `Bearer ${r.token}`, { node: 'node-a', shape: 'fixtureRead' });
    expect(again.ok).toBe(false);
    if (!again.ok) expect(again.code).toBe('OBO_NOT_DELEGABLE');
  });

  test('an unauthenticated or forged caller is refused, and the refusal does not quote it', async () => {
    const forged = caller.slice(0, -4) + 'abcd';
    const r = await mintOnBehalfOf(`ApiKey ${actor}`, `ApiKey ${forged}`, { node: 'n', shape: 's' });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.status).toBe(403);
      expect(JSON.stringify(r)).not.toContain(forged);
    }
    const none = await mintOnBehalfOf(`ApiKey ${actor}`, '', { node: 'n', shape: 's' });
    expect(none.ok).toBe(false);
  });

  test('the actor must be a valid API key; a bearer actor is refused', async () => {
    const session = await sign({ sub: 'u', user_id: 'u', org_id: 'o', exp: Math.floor(Date.now() / 1000) + 60 }, process.env.JWT_SECRET || 'dev-secret-change-in-production', 'HS512');
    const r = await mintOnBehalfOf(`Bearer ${session}`, `ApiKey ${caller}`, { node: 'n', shape: 's' });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.status).toBe(401);
  });

  test('a missing audience is refused', async () => {
    const r = await mintOnBehalfOf(`ApiKey ${actor}`, `ApiKey ${caller}`, { node: 'n' });
    expect(r.ok).toBe(false);
  });
});

describe('validating an OBO token', () => {
  test('plain verification reports the caller and the OBO binding', async () => {
    const r = await mint();
    const v = await verifyToken(r.token, { allowObo: true });
    expect(v.valid).toBe(true);
    expect(v.user_id).toBe('users:caller');
    expect(v.obo?.node).toBe('node-a');
    expect(v.obo?.shape).toBe('fixtureRead');
  });

  test('a validator naming another node or shape refuses it', async () => {
    const r = await mint('node-a', 'fixtureRead');
    expect((await verifyToken(r.token, { allowObo: true, audience: { node: 'node-b', shape: 'fixtureRead' } })).valid).toBe(false);
    expect((await verifyToken(r.token, { allowObo: true, audience: { node: 'node-a', shape: 'otherShape' } })).valid).toBe(false);
    expect((await verifyToken(r.token, { allowObo: true, audience: { node: 'node-a', shape: 'fixtureRead' } })).valid).toBe(true);

    const auth = (aud: { node: string; shape: string }) =>
      resolveAuthentication({ type: 'authentication', pointer: { type: 'session', token: r.token } } as any, aud);
    expect((await auth({ node: 'node-b', shape: 'fixtureRead' })).authenticated).toBe(false);
    expect((await auth({ node: 'node-a', shape: 'otherShape' })).authenticated).toBe(false);
    const ok = await auth({ node: 'node-a', shape: 'fixtureRead' });
    expect(ok.authenticated).toBe(true);
    expect(ok.userId).toBe('users:caller');
    expect(ok.keyId).toBe(callerKeyId);
  });

  test('privileged routes refuse it: default verification and admin authorization', async () => {
    const r = await mint();
    expect((await verifyToken(r.token)).valid).toBe(false);
    const admin = await authorizeAdmin(`Bearer ${r.token}`);
    expect(admin.ok).toBe(false);
  });
});
