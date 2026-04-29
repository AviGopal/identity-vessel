/**
 * Tests for the admin-only key issuance resolver.
 *
 * Covers the four mandated scenarios:
 *   1. Admin can issue a key with custom scopes
 *   2. Non-admin gets 403
 *   3. Generated key authenticates via existing validateKey() flow (round-trip)
 *   4. Persisted api_key row carries the right fields (mocked DB)
 *
 * Plus essential guards (missing header, malformed key) so the contract is
 * locked. Redis + SurrealDB are mocked at module load time.
 */

import { test, expect, describe, beforeEach, afterEach, mock } from 'bun:test';

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
  getSurrealDB: async () => {
    throw new Error('SurrealDB stubbed in issue-key test');
  },
}));

import { issueApiKey, setQueryFn } from './issue-key';
import { generateApiKey } from '../services/keyGeneration';
import { setQueryFn as setValidationQueryFn, validateKey } from '../services/validation';
import { sign as signJwt } from 'hono/jwt';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';

describe('issueApiKey — admin-only key issuance', () => {
  beforeEach(() => {
    setQueryFn(null);
    setValidationQueryFn(null);
  });
  afterEach(() => {
    setQueryFn(null);
    setValidationQueryFn(null);
  });

  test('admin (ApiKey + admin scope) issues a key with custom scopes', async () => {
    const adminKey = generateApiKey('metabob', 'users:admin', {});
    setValidationQueryFn(async () => [{ scopes: ['admin'] }]);

    const captured: { sql: string | null; params: Record<string, any> | null } = {
      sql: null, params: null,
    };
    setQueryFn(async (sql, params) => {
      captured.sql = sql;
      captured.params = params ?? null;
      return [];
    });

    const result = await issueApiKey(
      {
        user_id: 'users:newuser',
        org_id: 'organizations:metabob',
        scopes: ['read', 'write', 'admin'],
        expires_in_days: 30,
      },
      `ApiKey ${adminKey.key}`,
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.key.startsWith('mb-')).toBe(true);
      expect(result.key_id.startsWith('key_')).toBe(true);
      expect(result.expires_at).toBeDefined();
    }
    expect(captured.sql).toContain('CREATE');
    expect(captured.sql).toContain('api_key');
    expect(captured.params?.scopes).toEqual(['read', 'write', 'admin']);
  });

  test('admin (Bearer JWT role=admin) can issue a key', async () => {
    const adminToken = await signJwt(
      {
        iss: 'https://identity.metabob.com',
        sub: 'users:admin',
        org_id: 'metabob',
        user_id: 'users:admin',
        role: 'admin',
        exp: Math.floor(Date.now() / 1000) + 3600,
      },
      JWT_SECRET,
      'HS256',
    );
    setQueryFn(async () => []);

    const result = await issueApiKey(
      { user_id: 'users:bob', org_id: 'organizations:metabob' },
      `Bearer ${adminToken}`,
    );
    expect(result.ok).toBe(true);
  });

  test('non-admin ApiKey caller gets 403 and no DB write', async () => {
    const memberKey = generateApiKey('metabob', 'users:member', {});
    setValidationQueryFn(async () => [{ scopes: ['read', 'write'] }]);

    let dbCalls = 0;
    setQueryFn(async () => {
      dbCalls++;
      return [];
    });

    const result = await issueApiKey(
      { user_id: 'users:bob', org_id: 'organizations:metabob' },
      `ApiKey ${memberKey.key}`,
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.status).toBe(403);
      expect(result.code).toBe('FORBIDDEN');
    }
    expect(dbCalls).toBe(0);
  });

  test('missing or malformed auth → 401', async () => {
    const noHeader = await issueApiKey(
      { user_id: 'users:bob', org_id: 'organizations:metabob' },
      undefined,
    );
    const badKey = await issueApiKey(
      { user_id: 'users:bob', org_id: 'organizations:metabob' },
      'ApiKey mb-not-a-real-key-bad',
    );
    expect(noHeader.ok).toBe(false);
    expect(badKey.ok).toBe(false);
    if (!noHeader.ok) expect(noHeader.code).toBe('MISSING_AUTH_HEADER');
    if (!badKey.ok) expect(badKey.code).toBe('INVALID_API_KEY');
  });

  test('generated key authenticates via validateKey() round-trip', async () => {
    const adminKey = generateApiKey('metabob', 'users:admin', {});
    setValidationQueryFn(async () => [{ scopes: ['admin'] }]);
    setQueryFn(async () => []);

    const issued = await issueApiKey(
      {
        user_id: 'users:bob',
        org_id: 'organizations:metabob',
        scopes: ['read', 'write'],
      },
      `ApiKey ${adminKey.key}`,
    );

    expect(issued.ok).toBe(true);
    if (!issued.ok) return;

    // Simulate the persisted row backing F-NN-I lookupKeyScopes.
    setValidationQueryFn(async (_sql, params) => {
      expect(params?.key_id).toBe(issued.key_id);
      return [{ scopes: ['read', 'write'] }];
    });

    const validation = await validateKey(issued.key);
    expect(validation.valid).toBe(true);
    expect(validation.orgId).toBe('organizations:metabob');
    expect(validation.userId).toBe('users:bob');
    expect(validation.keyId).toBe(issued.key_id);
    expect(validation.scopes).toEqual(['read', 'write']);
  });

  test('persisted CREATE carries key_hash, scopes, org_id, user_id, expires_at', async () => {
    const adminKey = generateApiKey('metabob', 'users:admin', {});
    setValidationQueryFn(async () => [{ scopes: ['admin'] }]);

    let captured: { sql: string; params: Record<string, any> } | null = null;
    setQueryFn(async (sql, params) => {
      captured = { sql, params: params ?? {} };
      return [];
    });

    const result = await issueApiKey(
      {
        user_id: 'users:bob',
        org_id: 'organizations:metabob',
        scopes: ['read'],
        expires_in_days: 7,
      },
      `ApiKey ${adminKey.key}`,
    );

    expect(result.ok).toBe(true);
    expect(captured).not.toBeNull();
    if (!captured) return;
    const cap = captured as { sql: string; params: Record<string, any> };

    expect(cap.sql).toContain('CREATE api_key SET');
    expect(cap.sql).toContain('key_id = $key_id');
    if (result.ok) expect(cap.params.key_id).toBe(result.key_id);

    expect(cap.params.key_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(cap.sql).toContain('org_id = $org_id');
    expect(cap.sql).toContain('user_id = $user_id');
    expect(cap.params.org_id).toBe('organizations:metabob');
    expect(cap.params.user_id).toBe('users:bob');
    expect(cap.params.scopes).toEqual(['read']);
    expect(typeof cap.params.expires_at).toBe('string');
    expect(cap.sql).toContain('is_active = true');
    expect(cap.sql).toContain('created_at = time::now()');
  });

  test('missing user_id or org_id → 400 INVALID_INPUT', async () => {
    const adminKey = generateApiKey('metabob', 'users:admin', {});
    setValidationQueryFn(async () => [{ scopes: ['admin'] }]);
    const auth = `ApiKey ${adminKey.key}`;
    const noUser = await issueApiKey({ org_id: 'organizations:metabob' }, auth);
    const noOrg = await issueApiKey({ user_id: 'users:bob' }, auth);
    expect(noUser.ok).toBe(false);
    expect(noOrg.ok).toBe(false);
    if (!noUser.ok) expect(noUser.code).toBe('INVALID_INPUT');
    if (!noOrg.ok) expect(noOrg.code).toBe('INVALID_INPUT');
  });
});
