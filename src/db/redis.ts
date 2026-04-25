/**
 * Redis client for fast revocation checks
 */

import Redis from 'ioredis';

const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';

// Create Redis client
export const redis = new Redis(REDIS_URL, {
  retryStrategy: (times) => {
    const delay = Math.min(times * 50, 2000);
    return delay;
  },
  maxRetriesPerRequest: 3,
  enableReadyCheck: true,
  lazyConnect: false
});

// Handle connection events
redis.on('connect', () => {
  console.log('[Redis] Connected to Redis');
});

redis.on('error', (err) => {
  console.error('[Redis] Connection error:', err);
});

/**
 * Check if an API key is revoked (fast cache lookup)
 */
export async function isKeyRevoked(keyId: string): Promise<boolean> {
  try {
    const result = await redis.get('revoked:' + keyId);
    return result === '1';
  } catch (error) {
    console.error('[Redis] Failed to check revocation:', error);
    // Fail open - allow request if Redis is down
    return false;
  }
}

/**
 * Mark an API key as revoked
 */
export async function revokeKey(keyId: string, ttlSeconds: number = 31536000): Promise<void> {
  try {
    await redis.setex('revoked:' + keyId, ttlSeconds, '1');
  } catch (error) {
    console.error('[Redis] Failed to revoke key:', error);
    throw error;
  }
}

/**
 * Remove revocation (un-revoke a key)
 */
export async function unrevokeKey(keyId: string): Promise<void> {
  try {
    await redis.del('revoked:' + keyId);
  } catch (error) {
    console.error('[Redis] Failed to unrevoke key:', error);
    throw error;
  }
}

/**
 * Build a namespaced rate-limit key for Redis sorted sets.
 */
export function getRateLimitKey(endpoint: string, ip: string): string {
  return `ratelimit:${endpoint}:${ip}`;
}

/**
 * Sliding-window rate limiter using Redis sorted sets.
 *
 * Algorithm:
 *   1. Prune entries older than the 60-second window.
 *   2. Count remaining entries.
 *   3. If count >= limit → deny and report how long until the window resets.
 *   4. Otherwise record this request and allow it.
 *
 * Fails open: if Redis is unavailable the request is allowed and the error is
 * logged so traffic is never silently dropped due to an infrastructure problem.
 */
export async function checkRateLimit(
  key: string,
  limitPerMinute: number,
): Promise<{ allowed: boolean; retryAfterSeconds: number }> {
  try {
    const now = Date.now();
    const windowStart = now - 60_000;

    // Remove entries outside the 60-second sliding window
    await redis.zremrangebyscore(key, '-inf', windowStart);

    // Count requests still inside the window
    const count = await redis.zcard(key);

    if (count >= limitPerMinute) {
      return { allowed: false, retryAfterSeconds: 60 };
    }

    // Record this request (score = timestamp, member = timestamp for uniqueness)
    await redis.zadd(key, now, String(now));
    // Keep the key alive for slightly longer than the window to avoid races
    await redis.expire(key, 70);

    return { allowed: true, retryAfterSeconds: 0 };
  } catch (error) {
    // Fail open — do not block traffic if Redis is unavailable
    console.error('[Redis] Rate-limit check failed, failing open:', error);
    return { allowed: true, retryAfterSeconds: 0 };
  }
}
