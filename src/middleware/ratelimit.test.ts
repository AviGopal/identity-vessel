/**
 * Tests for rate-limit bucket-key strategies.
 *
 * Audit 2026-05-16: /v1/auth/resolve was IP-only at 20 req/min. Verify that
 * the new `bucketKeyIpAndApiKeyPrefix` strategy combines IP with the first 8
 * chars of an ApiKey header so distinct callers behind a shared NAT IP get
 * distinct buckets, falling back to IP-only when no key is present.
 */

import { test, expect, describe } from 'bun:test';
import { bucketKeyIpAndApiKeyPrefix } from './ratelimit';
import type { Context } from 'hono';

function fakeCtx(headers: Record<string, string>): Context {
  return {
    req: {
      header: (name: string) => headers[name],
    },
  } as unknown as Context;
}

describe('bucketKeyIpAndApiKeyPrefix', () => {
  test('combines IP with first 8 chars of ApiKey when present', () => {
    const c = fakeCtx({ Authorization: 'ApiKey mb-canary-abcdef-deadbeef' });
    const key = bucketKeyIpAndApiKeyPrefix(c, '10.0.0.1');
    expect(key).toBe('10.0.0.1:mb-canar');
  });

  test('falls back to IP-only when no Authorization header', () => {
    const c = fakeCtx({});
    expect(bucketKeyIpAndApiKeyPrefix(c, '10.0.0.1')).toBe('10.0.0.1');
  });

  test('falls back to IP-only when Authorization is Bearer (JWT)', () => {
    const c = fakeCtx({ Authorization: 'Bearer eyJhbGciOiJI...' });
    expect(bucketKeyIpAndApiKeyPrefix(c, '10.0.0.1')).toBe('10.0.0.1');
  });

  test('different keys on same IP produce distinct buckets', () => {
    const c1 = fakeCtx({ Authorization: 'ApiKey mb-alpha-aaaa' });
    const c2 = fakeCtx({ Authorization: 'ApiKey mb-bravo-bbbb' });
    const k1 = bucketKeyIpAndApiKeyPrefix(c1, '10.0.0.1');
    const k2 = bucketKeyIpAndApiKeyPrefix(c2, '10.0.0.1');
    expect(k1).not.toBe(k2);
  });

  test('same key on same IP shares a bucket', () => {
    const c1 = fakeCtx({ Authorization: 'ApiKey mb-alpha-aaaa-1111' });
    const c2 = fakeCtx({ Authorization: 'ApiKey mb-alpha-aaaa-2222' });
    // first 8 chars after "ApiKey " are identical → same bucket
    expect(bucketKeyIpAndApiKeyPrefix(c1, '10.0.0.1')).toBe(
      bucketKeyIpAndApiKeyPrefix(c2, '10.0.0.1'),
    );
  });

  test('different IPs always produce distinct buckets even with same key', () => {
    const c = fakeCtx({ Authorization: 'ApiKey mb-alpha-aaaa' });
    expect(bucketKeyIpAndApiKeyPrefix(c, '10.0.0.1')).not.toBe(
      bucketKeyIpAndApiKeyPrefix(c, '10.0.0.2'),
    );
  });
});
