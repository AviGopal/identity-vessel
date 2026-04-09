/**
 * Fast API key validation with HMAC signature verification
 */

import { createHmac, timingSafeEqual } from 'crypto';
import type { ApiKeyComponents, ValidationResult } from '../types';

// Environment configuration
const SECRET_KEY = process.env.API_KEY_SECRET || 'dev-secret-change-in-production';
const VALID_PREFIXES = ['mb_live', 'mb_test'];

/**
 * Parse API key into components
 * Format: mb_{env}-{org_id}-{user_id}-{key_id}-{hmac_signature}
 * Using dashes as separators for clarity
 */
export function parseApiKey(apiKey: string): ApiKeyComponents | null {
  try {
    const parts = apiKey.split('-');

    // Validate format: prefix + org + user + key + signature = 5 parts
    if (parts.length !== 5) {
      return null;
    }

    const prefix = parts[0] as 'mb_live' | 'mb_test';

    if (!VALID_PREFIXES.includes(prefix)) {
      return null;
    }

    // Extract components (no ambiguity since we use dashes as separators)
    const orgId = parts[1];
    const userId = parts[2];
    const keyId = parts[3];
    const signature = parts[4];

    return {
      prefix,
      orgId,
      userId,
      keyId,
      signature
    };
  } catch (error) {
    // Malformed key
    return null;
  }
}

/**
 * Verify HMAC signature using constant-time comparison
 */
export function verifySignature(components: ApiKeyComponents): boolean {
  const { prefix, orgId, userId, keyId, signature: providedSignature } = components;
  
  // Create payload (what was originally signed)
  const payload = `${prefix}.${orgId}.${userId}.${keyId}`;
  
  // Calculate expected signature
  const expectedSignature = createHmac('sha256', SECRET_KEY)
    .update(payload)
    .digest('hex')
    .slice(0, 32); // Truncate to 32 chars for shorter keys
  
  // Constant-time comparison to prevent timing attacks
  const providedBuffer = Buffer.from(providedSignature);
  const expectedBuffer = Buffer.from(expectedSignature);
  
  if (providedBuffer.length !== expectedBuffer.length) {
    return false;
  }
  
  return timingSafeEqual(providedBuffer, expectedBuffer);
}

/**
 * Validate API key format and signature (fast path - no DB)
 * This is the first line of defense - rejects invalid keys in <10μs
 */
export function validateKeyFormat(apiKey: string): ValidationResult {
  // Parse key
  const components = parseApiKey(apiKey);
  
  if (!components) {
    return {
      valid: false,
      error: 'Invalid API key format'
    };
  }
  
  // Verify signature
  if (!verifySignature(components)) {
    return {
      valid: false,
      error: 'Invalid API key signature'
    };
  }
  
  // Format and signature are valid
  return {
    valid: true,
    orgId: components.orgId,
    userId: components.userId,
    keyId: components.keyId
  };
}
