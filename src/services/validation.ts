/**
 * Fast API key validation with HMAC signature verification.
 *
 * Two-layer validation:
 *   1. validateKeyFormat()  — synchronous, format + HMAC only (no DB).
 *   2. validateKey()        — async, format + HMAC + DB-backed scope lookup.
 *
 * F-NN-I (2026-04-28): API-key auth previously hardcoded `scopes: ['read','write']`,
 * making admin operations dispatched via API key impossible.  validateKey()
 * now reads the `scopes` field from the api_keys row (when present) so admin-
 * scoped keys can authenticate destructive operations.  When the row is
 * missing or has no scopes column we fall through to the legacy default to
 * preserve existing canary auth flows (graceful degradation).
 */

import { createHmac, timingSafeEqual } from 'crypto';
import type { ApiKeyComponents, ValidationResult } from '../types';

// Environment configuration
const SECRET_KEY = process.env.API_KEY_SECRET || 'dev-secret-change-in-production';

// Lazy-imported query function so that validation.ts has no hard dependency
// on SurrealDB at module-load time (keeps the synchronous fast-path test-clean).
type QueryFn = (sql: string, params?: Record<string, any>) => Promise<any>;
let queryOverride: QueryFn | null = null;

/**
 * Test-only: substitute the SurrealDB query function used by lookupKeyScopes.
 * Pass null to reset to the default (real SurrealDB connection).
 */
export function setQueryFn(fn: QueryFn | null): void {
  queryOverride = fn;
}

async function getQueryFn(): Promise<QueryFn> {
  if (queryOverride) return queryOverride;
  const mod = await import('../db/surrealdb');
  return mod.query as QueryFn;
}

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

/**
 * Look up the scopes for an api_key row by its embedded keyId.
 *
 * Returns the row's `scopes` array if found, otherwise null.  Never throws —
 * any DB error (connection refused, missing namespace, query syntax error)
 * is logged and returns null so the caller can fall back to default scopes.
 *
 * The keyId embedded in the HMAC payload (e.g. "key_xyz123") is matched against
 * the api_keys table.  Two lookup strategies are attempted to remain forward-
 * compatible across schema variants:
 *   1. Direct record-id lookup (id = api_keys:<keyId>)
 *   2. key_prefix field match (current user-vessel schema uses this)
 *
 * If the row does not have a `scopes` field at all (current schema does not
 * define one yet — see F-NN-I in the project CLAUDE.md), null is returned and
 * the caller falls back to the legacy default.
 */
export async function lookupKeyScopes(keyId: string): Promise<string[] | null> {
  if (!keyId) return null;

  try {
    const query = await getQueryFn();

    // Try both lookup strategies in a single round-trip via SurrealDB's
    // multi-statement query support.  The first non-empty result wins.
    const result = await query(
      `SELECT scopes FROM api_keys WHERE id = type::thing("api_keys", $key_id) OR key_prefix = $key_id LIMIT 1;`,
      { key_id: keyId }
    );

    // SurrealDB returns the result set directly via our query() helper.
    const rows = Array.isArray(result) ? result : (result?.result ?? []);
    if (!Array.isArray(rows) || rows.length === 0) {
      return null;
    }

    const scopes = rows[0]?.scopes;
    if (!Array.isArray(scopes) || scopes.length === 0) {
      return null;
    }

    // Defensive: ensure every entry is a string before returning.
    return scopes.every((s) => typeof s === 'string') ? scopes : null;
  } catch (error) {
    // Graceful degradation: log once, return null so caller uses defaults.
    console.warn('[validation] lookupKeyScopes failed, falling back to defaults', {
      key_id: keyId,
      error: error instanceof Error ? error.message : String(error),
    });
    return null;
  }
}

/**
 * Full validation: format + HMAC + DB-backed scope lookup.
 *
 * This is the path that auth-resolve and the /v1/keys/validate endpoint use
 * when they need the caller's scope set.  validateKeyFormat() remains the
 * synchronous fast-path for callers that only need format/signature checks
 * (e.g. revocation, which only needs the keyId).
 */
export async function validateKey(apiKey: string): Promise<ValidationResult> {
  const result = validateKeyFormat(apiKey);

  if (!result.valid || !result.keyId) {
    return result;
  }

  const scopes = await lookupKeyScopes(result.keyId);
  if (scopes !== null) {
    return { ...result, scopes };
  }

  return result;
}
