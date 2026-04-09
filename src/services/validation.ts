/**
 * Fast API key validation with HMAC signature verification
 */

import { createHmac, timingSafeEqual } from 'crypto';
import type { ApiKeyComponents, ValidationResult } from '../types';

// Environment configuration
const SECRET_KEY = process.env.API_KEY_SECRET || 'dev-secret-change-in-production';

/**
 * Parse API key into components
 * Format: mb-[base64(signed-payload)]-{signature}
 * Where signed-payload = {org-id}-{member-id}-{key-id}-{iss}
 */
export function parseApiKey(apiKey: string): ApiKeyComponents | null {
  try {
    // Must start with 'mb-'
    if (!apiKey.startsWith('mb-')) {
      return null;
    }

    // Remove 'mb-' prefix
    const withoutPrefix = apiKey.substring(3);

    // Split on the LAST dash to separate payload from signature
    // This is important because base64url encoding can contain dashes
    const lastDashIndex = withoutPrefix.lastIndexOf('-');

    if (lastDashIndex === -1) {
      return null; // No signature separator found
    }

    const prefix = 'mb';
    const encodedPayload = withoutPrefix.substring(0, lastDashIndex);
    const signature = withoutPrefix.substring(lastDashIndex + 1);

    // Decode the base64 payload
    let signedPayload: string;
    try {
      signedPayload = Buffer.from(encodedPayload, 'base64url').toString('utf-8');
    } catch {
      return null; // Invalid base64
    }

    // Parse signed payload: {org-id}-{member-id}-{key-id}-{iss}
    const payloadParts = signedPayload.split('-');

    if (payloadParts.length < 4) {
      return null; // Missing required fields
    }

    // Extract components
    const orgId = payloadParts[0];
    const userId = payloadParts[1];
    const keyId = payloadParts[2];
    const iss = payloadParts.slice(3).join('-'); // Handle dashes in issuer URL

    return {
      prefix,
      orgId,
      userId,
      keyId,
      iss,
      encodedPayload,
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
  const { encodedPayload, signature: providedSignature } = components;

  // Reconstruct what was signed: mb-[base64-payload]
  const finalPayload = `mb-${encodedPayload}`;

  // Calculate expected signature
  const expectedSignature = createHmac('sha256', SECRET_KEY)
    .update(finalPayload)
    .digest('hex')
    .slice(0, 32); // Truncate to 32 chars for reasonable key length

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
  // Check for empty key
  if (!apiKey || apiKey.trim() === '') {
    return {
      valid: false,
      error: 'API key cannot be empty'
    };
  }

  // Check prefix
  if (!apiKey.startsWith('mb-')) {
    return {
      valid: false,
      error: 'Invalid API key prefix (must start with mb-)'
    };
  }

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
