/**
 * API key generation with HMAC signatures
 */

import { createHmac } from 'crypto';
import { customAlphabet } from 'nanoid';
import type { KeyGenerationOptions, KeyGenerationResult } from '../types';

const SECRET_KEY = process.env.API_KEY_SECRET || 'dev-secret-change-in-production';

// Custom nanoid without dashes (dash is our separator)
// Using: A-Z, a-z, 0-9, _
const nanoid = customAlphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_', 16);

/**
 * Generate a new API key with HMAC signature
 *
 * Format: mb-[base64(signed-payload)]-{signature}
 * Where signed-payload = {org-id}-{member-id}-{key-id}-{iss}
 *
 * Philosophy:
 * - No stable/unstable dichotomy - all keys are production-ready
 * - Accept errors for learning, failover to reliable pathways
 * - Never lose traces, templates, or execution provenance
 */
export function generateApiKey(
  orgId: string,
  userId: string,
  options: KeyGenerationOptions = {}
): KeyGenerationResult {
  // Generate unique key ID (without dashes)
  const keyId = 'key_' + nanoid();

  // Issuer - identity vessel endpoint or default
  const iss = process.env.IDENTITY_ENDPOINT || 'https://identity.metabob.com';

  // Create signed payload: {org-id}-{member-id}-{key-id}-{iss}
  const signedPayload = `${orgId}-${userId}-${keyId}-${iss}`;

  // Sign the payload with HMAC
  const payloadSignature = createHmac('sha256', SECRET_KEY)
    .update(signedPayload)
    .digest('hex');

  // Base64 encode the signed payload for transport
  const encodedPayload = Buffer.from(signedPayload).toString('base64url');

  // Generate final signature over the entire structure
  const finalPayload = `mb-${encodedPayload}`;
  const signature = createHmac('sha256', SECRET_KEY)
    .update(finalPayload)
    .digest('hex')
    .slice(0, 32); // Truncate for reasonable key length

  // Construct full API key: mb-[base64(signed-payload)]-{signature}
  const key = `${finalPayload}-${signature}`;

  // Calculate expiration if specified
  const expiresAt = options.expiresInDays
    ? new Date(Date.now() + options.expiresInDays * 24 * 60 * 60 * 1000).toISOString()
    : undefined;

  return {
    key,
    keyId,
    prefix: 'mb', // Always 'mb', no environment distinction
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
