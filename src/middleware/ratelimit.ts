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
import { checkRateLimit, getRateLimitKey } from '../db/redis';

// Parse allowlist once at module load time for O(1) lookups.
const ALLOWLIST_IPS: Set<string> = new Set(
  (process.env.RATE_LIMIT_ALLOWLIST_IPS || '')
    .split(',')
    .map((ip) => ip.trim())
    .filter(Boolean),
);

/**
 * Extract the caller IP from standard proxy headers or fall back to a
 * placeholder that still participates in rate limiting (so callers without
 * a forwarded-for header all share a single bucket rather than being skipped).
 */
function extractIp(c: Context): string {
  const forwarded = c.req.header('x-forwarded-for');
  if (forwarded) {
    // x-forwarded-for may contain a comma-separated chain; first entry is the
    // original client IP.
    const first = forwarded.split(',')[0].trim();
    if (first) return first;
  }
  return 'unknown';
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
    const ip = extractIp(c);

    // Allowlisted IPs bypass rate limiting entirely.
    if (ALLOWLIST_IPS.has(ip)) {
      return next();
    }

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
