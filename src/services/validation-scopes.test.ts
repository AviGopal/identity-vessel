/**
 * Tests for DB-backed scope lookup for API-key auth.
 *
 * Covers:
 *   - validateKey() returns scopes from the api_key row when present
 *   - admin scope flows through end-to-end
 *   - Falls back to default scopes when row is missing
 *   - Falls back to default scopes when DB throws
 *   - Falls back to default scopes when row has no scopes field
 *   - Malformed keys are rejected without DB lookup
 *
 * The SurrealDB query function is mocked via setQueryFn — no live DB needed.
 */

import { test, expect, describe, beforeEach, afterEach } from 'bun:test';
import {
  validateKey,
  validateKeyFormat,
  lookupKeyScopes,
  setQueryFn,
} from './validation';
import { generateApiKey } from './keyGeneration';

describe('DB-backed scope lookup', () => {
  beforeEach(() => {
    setQueryFn(null);
  });
  afterEach(() => {
    setQueryFn(null);
  });

  test('validateKey returns admin scopes when DB row has scopes:[admin]', async () => {
    const generated = generateApiKey('metabob', 'users:admin', {});
    let queryParams: Record<string, any> | undefined;

    setQueryFn(async (_sql: string, params?: Record<string, any>) => {
      queryParams = params;
      return [{ scopes: ['admin'] }];
    });

    const result = await validateKey(generated.key);

    expect(result.valid).toBe(true);
    expect(result.orgId).toBe('metabob');
    expect(result.userId).toBe('users:admin');
    expect(result.keyId).toBe(generated.keyId);
    expect(result.scopes).toEqual(['admin']);
    // Confirms we passed the keyId to the lookup query.
    expect(queryParams?.key_id).toBe(generated.keyId);
  });

  test('validateKey returns read+write scopes when DB row has scopes:[read,write]', async () => {
    const generated = generateApiKey('metabob', 'users:bob', {});

    setQueryFn(async () => [{ scopes: ['read', 'write'] }]);

    const result = await validateKey(generated.key);

    expect(result.valid).toBe(true);
    expect(result.scopes).toEqual(['read', 'write']);
  });

  test('validateKey returns mixed scopes (admin + read + write) from DB', async () => {
    const generated = generateApiKey('metabob', 'users:owner', {});

    setQueryFn(async () => [{ scopes: ['admin', 'read', 'write'] }]);

    const result = await validateKey(generated.key);

    expect(result.valid).toBe(true);
    expect(result.scopes).toEqual(['admin', 'read', 'write']);
    expect(result.scopes?.includes('admin')).toBe(true);
  });

  test('validateKey leaves scopes undefined when key row not found in DB', async () => {
    const generated = generateApiKey('metabob', 'users:alice', {});

    setQueryFn(async () => []); // No rows returned.

    const result = await validateKey(generated.key);

    expect(result.valid).toBe(true);
    // scopes undefined — caller (resolveAPIKey) falls back to default.
    expect(result.scopes).toBeUndefined();
  });

  test('validateKey leaves scopes undefined when DB row has no scopes field', async () => {
    const generated = generateApiKey('metabob', 'users:alice', {});

    // Simulates current user-vessel schema: api_key row exists but has no
    // scopes column at all.
    setQueryFn(async () => [{ id: 'api_key:abc', key_prefix: 'key_xyz' }]);

    const result = await validateKey(generated.key);

    expect(result.valid).toBe(true);
    expect(result.scopes).toBeUndefined();
  });

  test('validateKey leaves scopes undefined when DB row has empty scopes array', async () => {
    const generated = generateApiKey('metabob', 'users:alice', {});

    setQueryFn(async () => [{ scopes: [] }]);

    const result = await validateKey(generated.key);

    expect(result.valid).toBe(true);
    // Empty array is treated as "no scopes information" so the caller can
    // apply the default — this matches the graceful-degradation contract.
    expect(result.scopes).toBeUndefined();
  });

  test('validateKey leaves scopes undefined when DB query throws', async () => {
    const generated = generateApiKey('metabob', 'users:alice', {});

    setQueryFn(async () => {
      throw new Error('ECONNREFUSED');
    });

    const result = await validateKey(generated.key);

    expect(result.valid).toBe(true);
    expect(result.scopes).toBeUndefined();
  });

  test('validateKey rejects malformed key without performing DB lookup', async () => {
    let dbCalls = 0;
    setQueryFn(async () => {
      dbCalls++;
      return [];
    });

    const result = await validateKey('mb-not-a-real-key-bad');

    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
    expect(dbCalls).toBe(0);
  });

  test('validateKey rejects empty key without performing DB lookup', async () => {
    let dbCalls = 0;
    setQueryFn(async () => {
      dbCalls++;
      return [];
    });

    const result = await validateKey('');

    expect(result.valid).toBe(false);
    expect(dbCalls).toBe(0);
  });

  test('validateKey rejects tampered signature without performing DB lookup', async () => {
    const generated = generateApiKey('metabob', 'users:alice', {});
    const parts = generated.key.split('-');
    parts[parts.length - 1] = 'tamperedsignature1234567890123';
    const tampered = parts.join('-');

    let dbCalls = 0;
    setQueryFn(async () => {
      dbCalls++;
      return [];
    });

    const result = await validateKey(tampered);

    expect(result.valid).toBe(false);
    expect(result.error).toContain('signature');
    expect(dbCalls).toBe(0);
  });

  test('validateKeyFormat (sync fast-path) is unchanged — no DB, no scopes', () => {
    const generated = generateApiKey('metabob', 'users:alice', {});
    // No setQueryFn() — fast-path must not touch the DB.
    const result = validateKeyFormat(generated.key);

    expect(result.valid).toBe(true);
    expect(result.scopes).toBeUndefined();
  });

  test('lookupKeyScopes returns null on missing key without throwing', async () => {
    setQueryFn(async () => []);
    const scopes = await lookupKeyScopes('key_does_not_exist');
    expect(scopes).toBeNull();
  });

  test('lookupKeyScopes returns null when keyId is empty', async () => {
    let dbCalls = 0;
    setQueryFn(async () => {
      dbCalls++;
      return [];
    });
    const scopes = await lookupKeyScopes('');
    expect(scopes).toBeNull();
    expect(dbCalls).toBe(0);
  });

  test('lookupKeyScopes filters out non-string scope entries defensively', async () => {
    setQueryFn(async () => [{ scopes: ['admin', 42, null] }]);
    const scopes = await lookupKeyScopes('key_xyz');
    // Mixed types → reject the whole array; let caller use default.
    expect(scopes).toBeNull();
  });

  test('lookupKeyScopes accepts result wrapped in { result: [...] } shape', async () => {
    // Defensive: SurrealDB clients sometimes return either a flat array or
    // a wrapped { result } object depending on driver version.
    setQueryFn(async () => ({ result: [{ scopes: ['admin'] }] }));
    const scopes = await lookupKeyScopes('key_xyz');
    expect(scopes).toEqual(['admin']);
  });
});
