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
 * Factory that returns a Hono middleware enforcing `limitPerMinute` requests
 * per unique client IP within a sliding 60-second window.
 *
 * @param endpoint     Short identifier used as part of the Redis key, e.g. "keys_validate"
 * @param limitPerMinute  Maximum allowed requests per minute per IP
 */
export function createRateLimitMiddleware(
  endpoint: string,
  limitPerMinute: number,
) {
  return async (c: Context, next: Next): Promise<Response | void> => {
    const ip = extractIp(c);

    // Allowlisted IPs bypass rate limiting entirely.
    if (ALLOWLIST_IPS.has(ip)) {
      return next();
    }

    const key = getRateLimitKey(endpoint, ip);
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
