/**
 * API key generation with HMAC signatures
 */

import { createHmac } from 'crypto';
import { nanoid } from 'nanoid';
import type { KeyGenerationOptions, KeyGenerationResult } from '../types';

const SECRET_KEY = process.env.API_KEY_SECRET || 'dev-secret-change-in-production';

/**
 * Generate a new API key with HMAC signature
 * Format: mb_live-<org_id>-<user_id>-<key_id>-<signature>
 * Using dashes as separators to avoid ambiguity with underscores in IDs
 */
export function generateApiKey(
  orgId: string,
  userId: string,
  options: KeyGenerationOptions = {}
): KeyGenerationResult {
  // Generate unique key ID (use alphabet without dashes to avoid ambiguity)
  const keyId = 'key_' + nanoid(16);

  // Determine prefix based on environment
  const prefix = process.env.NODE_ENV === 'production' ? 'mb_live' : 'mb_test';

  // Create payload to sign
  const payload = prefix + '.' + orgId + '.' + userId + '.' + keyId;

  // Generate HMAC signature
  const signature = createHmac('sha256', SECRET_KEY)
    .update(payload)
    .digest('hex')
    .slice(0, 32);

  // Construct full API key (using dashes as separators)
  // Format: mb_{env}-{org}-{user}-{key_id}-{signature}
  const key = prefix + '-' + orgId + '-' + userId + '-' + keyId + '-' + signature;

  // Calculate expiration if specified
  const expiresAt = options.expiresInDays
    ? new Date(Date.now() + options.expiresInDays * 24 * 60 * 60 * 1000).toISOString()
    : undefined;

  return {
    key,
    keyId,
    prefix,
    expiresAt
  };
}

/**
 * Generate metadata object for database storage
 * NOTE: NEVER store the full API key - only metadata!
 */
export function generateKeyMetadata(
  orgId: string,
  userId: string,
  keyId: string,
  prefix: string,
  options: KeyGenerationOptions = {}
) {
  return {
    id: keyId,
    org_id: orgId,
    user_id: userId,
    key_prefix: prefix,
    name: options.name || 'API Key ' + new Date().toISOString().split('T')[0],
    scopes: options.scopes || ['read', 'write'],
    created_at: new Date().toISOString(),
    expires_at: options.expiresInDays
      ? new Date(Date.now() + options.expiresInDays * 24 * 60 * 60 * 1000).toISOString()
      : undefined,
    is_active: true,
    usage_count: 0
  };
}
