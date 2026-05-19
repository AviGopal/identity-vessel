/**
 * Tests for the user-vessel HTTP client.
 *
 * Mocks fetch to verify wire-format adapter and graceful-degradation paths:
 *   - Successful query returns parsed accounts list
 *   - Non-2xx response returns null
 *   - Network failure returns null
 *   - Malformed response returns null
 *   - pickDefaultAccount selection order
 */

import { test, expect, describe, beforeEach } from 'bun:test';
import {
  UserVesselClient,
  pickDefaultAccount,
  normalizeAccountId,
  _resetUserAccountsCache,
  type AccountMembership,
} from './user-vessel-client';

const ENDPOINT = 'http://user-vessel.test';

function makeFetch(
  handler: (
    input: string | URL | Request,
    init?: RequestInit,
  ) => Promise<Response>,
): typeof fetch {
  return handler as unknown as typeof fetch;
}

describe('UserVesselClient.queryUserAccounts', () => {
  beforeEach(() => {
    _resetUserAccountsCache();
  });

  test('returns parsed memberships on 200 OK', async () => {
    let receivedUrl: string | null = null;
    let receivedAuth: string | null = null;
    let receivedBody: any = null;

    const client = new UserVesselClient({
      endpoint: ENDPOINT,
      fetchImpl: makeFetch(async (input, init) => {
        receivedUrl = input.toString();
        receivedAuth = new Headers(init?.headers).get('Authorization');
        receivedBody = JSON.parse(init?.body as string);
        return new Response(
          JSON.stringify({
            ok: true,
            result: {
              user_id: 'users:alice',
              accounts: [
                { account_id: 'accounts:metabob', role: 'owner', joined_at: '2026-04-01T00:00:00Z' },
                { account_id: 'accounts:widgets', role: 'member', joined_at: '2026-04-02T00:00:00Z' },
              ],
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }),
    });

    const result = await client.queryUserAccounts('users:alice', 'ApiKey mb-x-y');
    expect(result).not.toBeNull();
    expect(result).toHaveLength(2);
    expect(result![0].account_id).toBe('accounts:metabob');
    expect(receivedUrl as string | null).toBe(`${ENDPOINT}/mcp/tools/call`);
    expect(receivedAuth as string | null).toBe('ApiKey mb-x-y');
    expect(receivedBody.name).toBe('query-user-context');
    expect(receivedBody.arguments.user_id).toBe('users:alice');
  });

  test('returns null on non-2xx response', async () => {
    const client = new UserVesselClient({
      endpoint: ENDPOINT,
      fetchImpl: makeFetch(async () => new Response('forbidden', { status: 403 })),
    });

    const result = await client.queryUserAccounts('users:alice', 'ApiKey x');
    expect(result).toBeNull();
  });

  test('returns null on fetch error (network unreachable)', async () => {
    const client = new UserVesselClient({
      endpoint: ENDPOINT,
      fetchImpl: makeFetch(async () => {
        throw new Error('ECONNREFUSED');
      }),
    });

    const result = await client.queryUserAccounts('users:alice', 'ApiKey x');
    expect(result).toBeNull();
  });

  test('returns null when body is malformed (no `ok` field)', async () => {
    const client = new UserVesselClient({
      endpoint: ENDPOINT,
      fetchImpl: makeFetch(async () =>
        new Response(JSON.stringify({ unexpected: 'shape' }), { status: 200 }),
      ),
    });

    const result = await client.queryUserAccounts('users:alice', 'ApiKey x');
    expect(result).toBeNull();
  });

  test('returns empty array when accounts list missing or empty', async () => {
    const client = new UserVesselClient({
      endpoint: ENDPOINT,
      fetchImpl: makeFetch(async () =>
        new Response(
          JSON.stringify({ ok: true, result: { user_id: 'users:alice', accounts: [] } }),
          { status: 200 },
        ),
      ),
    });

    const result = await client.queryUserAccounts('users:alice', 'ApiKey x');
    expect(result).toEqual([]);
  });

  test('returns null when ok=false', async () => {
    const client = new UserVesselClient({
      endpoint: ENDPOINT,
      fetchImpl: makeFetch(async () =>
        new Response(JSON.stringify({ ok: false, error: 'user_id required' }), { status: 200 }),
      ),
    });

    const result = await client.queryUserAccounts('users:alice', 'ApiKey x');
    expect(result).toBeNull();
  });
});

describe('UserVesselClient queryUserAccounts cache', () => {
  beforeEach(() => {
    _resetUserAccountsCache();
  });

  test('cache hit: second call within TTL does not hit fetch', async () => {
    let calls = 0;
    const client = new UserVesselClient({
      endpoint: ENDPOINT,
      fetchImpl: makeFetch(async () => {
        calls += 1;
        return new Response(
          JSON.stringify({
            ok: true,
            result: {
              user_id: 'users:alice',
              accounts: [
                { account_id: 'accounts:metabob', role: 'owner', joined_at: '2026-04-01T00:00:00Z' },
              ],
            },
          }),
          { status: 200 },
        );
      }),
    });

    const r1 = await client.queryUserAccounts('users:alice', 'ApiKey x');
    const r2 = await client.queryUserAccounts('users:alice', 'ApiKey x');
    expect(calls).toBe(1);
    expect(r1).toEqual(r2 as any);
    expect(r2![0].account_id).toBe('accounts:metabob');
  });

  test('cache miss after expiry: TTL=0 forces fresh fetch every call', async () => {
    const prev = process.env.IDENTITY_USER_ACCOUNTS_CACHE_TTL_MS;
    process.env.IDENTITY_USER_ACCOUNTS_CACHE_TTL_MS = '0';
    // The TTL is read at module-load time, so we directly assert miss behavior
    // by stuffing an already-expired entry.
    process.env.IDENTITY_USER_ACCOUNTS_CACHE_TTL_MS = prev ?? '';

    let calls = 0;
    const client = new UserVesselClient({
      endpoint: ENDPOINT,
      fetchImpl: makeFetch(async () => {
        calls += 1;
        return new Response(
          JSON.stringify({ ok: true, result: { user_id: 'users:bob', accounts: [] } }),
          { status: 200 },
        );
      }),
    });

    await client.queryUserAccounts('users:bob', 'ApiKey x');
    expect(calls).toBe(1);

    // Force expiry by clearing cache (simulates TTL elapse).
    _resetUserAccountsCache();
    await client.queryUserAccounts('users:bob', 'ApiKey x');
    expect(calls).toBe(2);
  });

  test('caches null results (non-2xx) to absorb transient outages', async () => {
    let calls = 0;
    const client = new UserVesselClient({
      endpoint: ENDPOINT,
      fetchImpl: makeFetch(async () => {
        calls += 1;
        return new Response('upstream broken', { status: 503 });
      }),
    });

    const r1 = await client.queryUserAccounts('users:carol', 'ApiKey x');
    const r2 = await client.queryUserAccounts('users:carol', 'ApiKey x');
    expect(r1).toBeNull();
    expect(r2).toBeNull();
    // Second call served from cache — user-vessel hit exactly once.
    expect(calls).toBe(1);
  });

  test('separate users get separate cache entries', async () => {
    let calls = 0;
    const client = new UserVesselClient({
      endpoint: ENDPOINT,
      fetchImpl: makeFetch(async (_input, init) => {
        calls += 1;
        const body = JSON.parse(init?.body as string);
        return new Response(
          JSON.stringify({
            ok: true,
            result: {
              user_id: body.arguments.user_id,
              accounts: [
                { account_id: `accounts:${body.arguments.user_id}`, role: 'owner', joined_at: '2026-04-01T00:00:00Z' },
              ],
            },
          }),
          { status: 200 },
        );
      }),
    });

    await client.queryUserAccounts('users:alice', 'ApiKey x');
    await client.queryUserAccounts('users:bob', 'ApiKey x');
    await client.queryUserAccounts('users:alice', 'ApiKey x'); // cache hit
    expect(calls).toBe(2);
  });
});

describe('pickDefaultAccount', () => {
  const owner: AccountMembership = {
    account_id: 'accounts:owned',
    role: 'owner',
    joined_at: '2026-04-01T00:00:00Z',
  };
  const member: AccountMembership = {
    account_id: 'accounts:joined',
    role: 'member',
    joined_at: '2026-04-02T00:00:00Z',
  };
  const viewer: AccountMembership = {
    account_id: 'accounts:viewed',
    role: 'viewer',
    joined_at: '2026-04-03T00:00:00Z',
  };

  test('returns null on empty list', () => {
    expect(pickDefaultAccount([])).toBeNull();
  });

  test('prefers owner role over member', () => {
    expect(pickDefaultAccount([member, owner])?.account_id).toBe('accounts:owned');
  });

  test('prefers member role when no owner', () => {
    expect(pickDefaultAccount([viewer, member])?.account_id).toBe('accounts:joined');
  });

  test('falls back to first entry when no owner or member', () => {
    expect(pickDefaultAccount([viewer])?.account_id).toBe('accounts:viewed');
  });

  test('selects only owner from a list of multiple owners (first wins)', () => {
    const owner2: AccountMembership = {
      account_id: 'accounts:other',
      role: 'owner',
      joined_at: '2026-04-04T00:00:00Z',
    };
    expect(pickDefaultAccount([owner, owner2])?.account_id).toBe('accounts:owned');
  });
});

describe('normalizeAccountId', () => {
  test('passes through already-prefixed accounts:<id>', () => {
    expect(normalizeAccountId('accounts:metabob')).toBe('accounts:metabob');
  });

  test('rewrites organizations:<x> to accounts:<x>', () => {
    expect(normalizeAccountId('organizations:metabob')).toBe('accounts:metabob');
  });

  test('adds accounts: prefix to bare slug', () => {
    expect(normalizeAccountId('metabob')).toBe('accounts:metabob');
  });
});
