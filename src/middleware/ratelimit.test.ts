/**
 * Tests for rate-limit bucket-key strategies.
 *
 * Audit 2026-05-16: /v1/auth/resolve was IP-only at 20 req/min. Verify that
 * the new `bucketKeyIpAndApiKeyPrefix` strategy combines IP with the first 8
 * chars of an ApiKey header so distinct callers behind a shared NAT IP get
 * distinct buckets, falling back to IP-only when no key is present.
 */

import { test, expect, describe } from 'bun:test';
import { bucketIp, bucketKeyIpAndApiKeyPrefix, isAllowlisted } from './ratelimit';
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

// The allowlist is decided on the SOCKET PEER of a DIRECT caller, never on a header (2026-09-30): with only
// x-forwarded-for consulted, RATE_LIMIT_ALLOWLIST_IPS=127.0.0.1 could never match and a co-located fleet shared
// one 'unknown' bucket (~415 auth_resolve 429s/min on a 64-unit hub); trusting the header would let anyone claim it.
describe('allowlist decided on the direct socket peer', () => {
  const allow = new Set(['127.0.0.1', 'unknown']);

  test('a loopback peer with no forwarding header is allowlisted (in-container vessels)', () => {
    expect(isAllowlisted('127.0.0.1', undefined, allow)).toBe(true);
    expect(isAllowlisted('::ffff:127.0.0.1', undefined, allow)).toBe(true);
    expect(isAllowlisted('::1', undefined, allow)).toBe(true);
  });

  test('no connection info stays rate-limited, even when the env lists unknown', () => {
    expect(isAllowlisted(undefined, undefined, allow)).toBe(false);
    expect(bucketIp(undefined, undefined)).toBe('unknown');
  });

  test('a spoofed X-Forwarded-For: 127.0.0.1 from a non-loopback peer stays rate-limited', () => {
    expect(isAllowlisted('203.0.113.9', '127.0.0.1', allow)).toBe(false);
  });

  test('a proxied external caller arriving via a loopback relay stays limited in its own bucket', () => {
    expect(isAllowlisted('127.0.0.1', '198.51.100.7, 127.0.0.1', allow)).toBe(false);
    expect(bucketIp('127.0.0.1', '198.51.100.7, 127.0.0.1')).toBe('198.51.100.7');
  });

  test('a direct external caller cannot pick its own bucket with X-Forwarded-For (rate-limit evasion)', () => {
    expect(bucketIp('203.0.113.9', 'a.a.a.a')).toBe('203.0.113.9');
    expect(bucketIp('203.0.113.9', 'b.b.b.b')).toBe(bucketIp('203.0.113.9', 'a.a.a.a'));
    expect(bucketIp(undefined, 'c.c.c.c')).toBe('unknown');
  });

  test('a direct external caller is bucketed by its socket peer, not the shared placeholder', () => {
    expect(isAllowlisted('203.0.113.9', undefined, allow)).toBe(false);
    expect(bucketIp('203.0.113.9', undefined)).toBe('203.0.113.9');
  });
});
