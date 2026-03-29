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
