/**
 * Rate-limit middleware for Hono routes.
 *
 * Uses a sliding 60-second window implemented in Redis sorted sets.
 * See src/db/redis.ts for the underlying checkRateLimit / getRateLimitKey helpers.
 *
 * Fail-open: if Redis is down the middleware lets the request through so
 * infrastructure problems never silently block legitimate traffic.
 *
 * Allowlist: set RATE_LIMIT_ALLOWLIST_IPS to a comma-separated list of IPs
 * that should bypass rate limiting (e.g. internal health-checkers, CI agents).
 */

import type { Context, Next } from 'hono';
import { getConnInfo } from 'hono/bun';
import { checkRateLimit, getRateLimitKey } from '../db/redis';

// Parse allowlist once at module load time for O(1) lookups.
const ALLOWLIST_IPS: Set<string> = new Set(
  (process.env.RATE_LIMIT_ALLOWLIST_IPS || '')
    .split(',')
    .map((ip) => ip.trim())
    .filter(Boolean),
);

/** IPv4-mapped and IPv6 loopback read as 127.0.0.1, so one allowlist entry covers every loopback form. */
export function normalizePeer(addr: string | undefined): string | undefined {
  if (!addr) return undefined;
  const a = addr.trim();
  if (a === '::1') return '127.0.0.1';
  return a.startsWith('::ffff:') ? a.slice('::ffff:'.length) : a;
}

/** First hop of x-forwarded-for, or undefined when the header is absent or empty. */
function forwardedFirst(forwardedFor: string | undefined): string | undefined {
  const first = (forwardedFor ?? '').split(',')[0]?.trim();
  return first ? first : undefined;
}

/**
 * The ALLOWLIST is decided on the SOCKET PEER of a DIRECT caller, never on a header (2026-09-30).
 *
 * The old extractIp read only x-forwarded-for and returned 'unknown' otherwise, and 'unknown' is correctly never
 * allowlist-eligible, so RATE_LIMIT_ALLOWLIST_IPS=127.0.0.1 could never match: every in-container vessel (no
 * forwarding header) shared ONE 'unknown' bucket, and a 64-unit hub rate-limited itself (~415 auth_resolve 429s
 * per minute on syzygy.host). Deciding on the header instead would let any caller claim 127.0.0.1.
 *
 * So a request is allowlisted only when it carries NO x-forwarded-for (a proxied request, even one arriving from a
 * loopback relay, stays limited in its forwarded client's bucket) and its socket peer is known and listed.
 */
export function isAllowlisted(peer: string | undefined, forwardedFor: string | undefined, allowlist: Set<string>): boolean {
  if (forwardedFirst(forwardedFor) !== undefined) return false;
  const p = normalizePeer(peer);
  return p !== undefined && p !== 'unknown' && allowlist.has(p);
}

/** A peer whose x-forwarded-for may be believed: loopback only (an in-container proxy). identity is published on
 *  0.0.0.0, so any other caller can put anything in the header. */
function isTrustedProxy(peer: string | undefined): boolean {
  return normalizePeer(peer) === '127.0.0.1';
}

/**
 * The bucket IP: the socket peer; the forwarded client only when the peer is a trusted (loopback) proxy; else the
 * 'unknown' placeholder, which still participates in rate limiting. Believing x-forwarded-for from ANY caller let a
 * direct external caller send a new header per request and land in a fresh bucket every time: unlimited
 * auth_resolve / API-key validation (qa, 2026-09-30; pre-existing, fixable once the peer is known).
 */
export function bucketIp(peer: string | undefined, forwardedFor: string | undefined): string {
  const fwd = forwardedFirst(forwardedFor);
  if (fwd !== undefined && isTrustedProxy(peer)) return fwd;
  return normalizePeer(peer) ?? 'unknown';
}

/** The socket peer, or undefined when it cannot be determined (never guessed: an unnamed origin is not local). */
function socketPeer(c: Context): string | undefined {
  try {
    return getConnInfo(c).remote.address;
  } catch {
    return undefined;
  }
}

/**
 * Build the per-request bucket key, defaulting to IP-only.  Callers may
 * substitute a function that incorporates additional dimensions (e.g. the
 * API-key prefix) so that distinct callers behind a shared NAT IP don't
 * share a single bucket.
 *
 * Audit 2026-05-16: /v1/auth/resolve was IP-only at 20 req/min, which
 * caused 5-concurrent-request bursts from a single key to wedge entire
 * activity-api pods (multiple authentic callers behind a cluster egress IP
 * shared one bucket). Per-key bucketing fixes that without losing IP-level
 * abuse protection.
 */
export type BucketKeyFn = (c: Context, ip: string) => string;

/**
 * Default bucket key: IP only. Pre-existing rate-limited routes keep this.
 */
function defaultBucketKey(_c: Context, ip: string): string {
  return ip;
}

/**
 * Bucket key that combines IP with the first 8 chars of an API key (when
 * present in the Authorization header). When no key is present (e.g. Bearer
 * JWT, or impulse-form body), falls back to IP-only so the bucket still
 * exists. Used on /v1/auth/resolve per audit findings 2026-05-16.
 */
export function bucketKeyIpAndApiKeyPrefix(c: Context, ip: string): string {
  const authHeader = c.req.header('Authorization') || '';
  if (authHeader.startsWith('ApiKey ')) {
    const prefix = authHeader.slice('ApiKey '.length, 'ApiKey '.length + 8);
    if (prefix.length > 0) {
      return `${ip}:${prefix}`;
    }
  }
  return ip;
}

/**
 * Factory that returns a Hono middleware enforcing `limitPerMinute` requests
 * per bucket within a sliding 60-second window.
 *
 * @param endpoint     Short identifier used as part of the Redis key, e.g. "keys_validate"
 * @param limitPerMinute  Maximum allowed requests per minute per bucket
 * @param bucketKeyFn  Optional custom bucket-key function (default: IP only)
 */
export function createRateLimitMiddleware(
  endpoint: string,
  limitPerMinute: number,
  bucketKeyFn: BucketKeyFn = defaultBucketKey,
) {
  return async (c: Context, next: Next): Promise<Response | void> => {
    const peer = socketPeer(c);
    const forwardedFor = c.req.header('x-forwarded-for');

    // Allowlisted DIRECT callers bypass rate limiting entirely (see isAllowlisted).
    // SECURITY: the 'unknown' placeholder and an undeterminable peer are NEVER allowlist-eligible, even when a
    // deployment lists 'unknown' in RATE_LIMIT_ALLOWLIST_IPS (as this fleet did); a header is never trusted for it.
    if (isAllowlisted(peer, forwardedFor, ALLOWLIST_IPS)) {
      return next();
    }
    const ip = bucketIp(peer, forwardedFor);

    const bucket = bucketKeyFn(c, ip);
    const key = getRateLimitKey(endpoint, bucket);
    const { allowed, retryAfterSeconds } = await checkRateLimit(key, limitPerMinute);

    if (!allowed) {
      c.header('Retry-After', String(retryAfterSeconds));
      return c.json(
        {
          success: false,
          error: {
            code: 'RATE_LIMIT_EXCEEDED',
            message: `Too many requests. Please try again after ${retryAfterSeconds} seconds.`,
            retry_after_seconds: retryAfterSeconds,
          },
        },
        429,
      );
    }

    return next();
  };
}
