/**
 * Tests for account_id enrichment on auth resolution.
 *
 * Covers:
 *   - Successful API key validation populates `accountId` when user-vessel
 *     returns memberships
 *   - User-vessel unreachable → result still authenticated, `accountId`
 *     omitted (graceful degrade)
 *   - User has no memberships → `accountId` omitted
 *   - Default account selection uses owner > member > first-in-list
 *   - Failed authentication is NOT enriched (no spurious user-vessel call)
 */

import { test, expect, describe, beforeEach, afterEach, mock } from 'bun:test';

// Stub the redis module BEFORE importing anything that touches it.  The real
// module spins up an ioredis connection that retries and times out for
// several seconds when no Redis is reachable; that latency is irrelevant to
// account_id enrichment behavior.
mock.module('../db/redis', () => ({
  redis: {},
  isKeyRevoked: async () => false,
  revokeKey: async () => {},
  unrevokeKey: async () => {},
  getRateLimitKey: (endpoint: string, ip: string) => `ratelimit:${endpoint}:${ip}`,
  checkRateLimit: async () => ({ allowed: true, retryAfterSeconds: 0 }),
}));

// Stub the trace module — it tries to POST traces to activity-api on every
// auth resolution. Fire-and-forget today, but it can race with test teardown.
mock.module('../services/trace', () => ({
  traceAuthentication: <T,>(operation: () => Promise<T>) => operation(),
  sendAuthenticationTrace: async () => {},
}));

import { resolveAuthentication, setUserVesselClient } from './auth';
import { generateApiKey } from '../services/keyGeneration';
import {
  UserVesselClient,
  type AccountMembership,
} from '../services/user-vessel-client';

const ENDPOINT = 'http://user-vessel.test';

function makeClient(
  handler: (
    input: string | URL | Request,
    init?: RequestInit,
  ) => Promise<Response>,
): UserVesselClient {
  return new UserVesselClient({
    endpoint: ENDPOINT,
    fetchImpl: handler as unknown as typeof fetch,
  });
}

describe('auth-resolve account_id enrichment', () => {
  beforeEach(() => {
    setUserVesselClient(null);
  });
  afterEach(() => {
    setUserVesselClient(null);
  });

  // Each test waits up to 30s because the Redis revocation check (which we
  // do not mock) takes a few seconds to fail-open when no Redis is reachable.
  // Behavior is correct; the test just needs to outlast the connection timeout.
  test('populates accountId when user-vessel returns one membership', async () => {
    const generated = generateApiKey('metabob', 'users:alice', {});
    const client = makeClient(async () =>
      new Response(
        JSON.stringify({
          ok: true,
          result: {
            user_id: 'users:alice',
            accounts: [
              {
                account_id: 'accounts:metabob',
                role: 'owner',
                joined_at: '2026-04-01T00:00:00Z',
              },
            ],
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    );
    setUserVesselClient(client);

    const result = await resolveAuthentication({
      type: 'authentication',
      pointer: { type: 'apiKey', apiKey: generated.key },
    });

    expect(result.authenticated).toBe(true);
    expect(result.orgId).toBe('metabob');
    expect(result.userId).toBe('users:alice');
    expect(result.accountId).toBe('accounts:metabob');
  });

  test('omits accountId when user-vessel is unreachable (graceful degrade)', async () => {
    const generated = generateApiKey('metabob', 'users:alice', {});
    const client = makeClient(async () => {
      throw new Error('ECONNREFUSED');
    });
    setUserVesselClient(client);

    const result = await resolveAuthentication({
      type: 'authentication',
      pointer: { type: 'apiKey', apiKey: generated.key },
    });

    expect(result.authenticated).toBe(true);
    expect(result.orgId).toBe('metabob');
    expect(result.userId).toBe('users:alice');
    expect(result.accountId).toBeUndefined();
  });

  test('omits accountId when user has no memberships', async () => {
    const generated = generateApiKey('metabob', 'users:alice', {});
    const client = makeClient(async () =>
      new Response(
        JSON.stringify({ ok: true, result: { user_id: 'users:alice', accounts: [] } }),
        { status: 200 },
      ),
    );
    setUserVesselClient(client);

    const result = await resolveAuthentication({
      type: 'authentication',
      pointer: { type: 'apiKey', apiKey: generated.key },
    });

    expect(result.authenticated).toBe(true);
    expect(result.accountId).toBeUndefined();
  });

  test('selects owner role over member when user has multiple accounts', async () => {
    const generated = generateApiKey('metabob', 'users:alice', {});
    const memberships: AccountMembership[] = [
      // member listed first to verify the picker doesn't just take index 0
      {
        account_id: 'accounts:joined',
        role: 'member',
        joined_at: '2026-04-02T00:00:00Z',
      },
      {
        account_id: 'accounts:owned',
        role: 'owner',
        joined_at: '2026-04-01T00:00:00Z',
      },
    ];
    const client = makeClient(async () =>
      new Response(
        JSON.stringify({
          ok: true,
          result: { user_id: 'users:alice', accounts: memberships },
        }),
        { status: 200 },
      ),
    );
    setUserVesselClient(client);

    const result = await resolveAuthentication({
      type: 'authentication',
      pointer: { type: 'apiKey', apiKey: generated.key },
    });

    expect(result.accountId).toBe('accounts:owned');
  });

  test('falls back to first account when no owner or member role present', async () => {
    const generated = generateApiKey('metabob', 'users:alice', {});
    const memberships: AccountMembership[] = [
      {
        account_id: 'accounts:viewer-only',
        role: 'viewer',
        joined_at: '2026-04-01T00:00:00Z',
      },
      {
        account_id: 'accounts:another',
        role: 'viewer',
        joined_at: '2026-04-02T00:00:00Z',
      },
    ];
    const client = makeClient(async () =>
      new Response(
        JSON.stringify({
          ok: true,
          result: { user_id: 'users:alice', accounts: memberships },
        }),
        { status: 200 },
      ),
    );
    setUserVesselClient(client);

    const result = await resolveAuthentication({
      type: 'authentication',
      pointer: { type: 'apiKey', apiKey: generated.key },
    });

    expect(result.accountId).toBe('accounts:viewer-only');
  });

  test('does NOT call user-vessel when API key is invalid', async () => {
    let userVesselCalls = 0;
    const client = makeClient(async () => {
      userVesselCalls++;
      return new Response(JSON.stringify({ ok: true, result: { accounts: [] } }), {
        status: 200,
      });
    });
    setUserVesselClient(client);

    const result = await resolveAuthentication({
      type: 'authentication',
      pointer: { type: 'apiKey', apiKey: 'mb-not-a-real-key-bad' },
    });

    expect(result.authenticated).toBe(false);
    expect(result.accountId).toBeUndefined();
    expect(userVesselCalls).toBe(0);
  });

  test('normalizes bare account_id slug to accounts:<id>', async () => {
    const generated = generateApiKey('metabob', 'users:alice', {});
    const client = makeClient(async () =>
      new Response(
        JSON.stringify({
          ok: true,
          result: {
            user_id: 'users:alice',
            // user-vessel can return either a prefixed id or a bare slug —
            // identity-vessel should normalize either form.
            accounts: [
              { account_id: 'metabob', role: 'owner', joined_at: '2026-04-01T00:00:00Z' },
            ],
          },
        }),
        { status: 200 },
      ),
    );
    setUserVesselClient(client);

    const result = await resolveAuthentication({
      type: 'authentication',
      pointer: { type: 'apiKey', apiKey: generated.key },
    });

    expect(result.accountId).toBe('accounts:metabob');
  });

  test('forwards the caller\'s API key in the Authorization header', async () => {
    const generated = generateApiKey('metabob', 'users:alice', {});
    let receivedAuth: string | null = null;
    const client = makeClient(async (_url, init) => {
      receivedAuth = new Headers(init?.headers).get('Authorization');
      return new Response(
        JSON.stringify({
          ok: true,
          result: {
            accounts: [
              { account_id: 'accounts:metabob', role: 'owner', joined_at: 'x' },
            ],
          },
        }),
        { status: 200 },
      );
    });
    setUserVesselClient(client);

    await resolveAuthentication({
      type: 'authentication',
      pointer: { type: 'apiKey', apiKey: generated.key },
    });

    expect(receivedAuth as string | null).toBe(`ApiKey ${generated.key}`);
  });
});
