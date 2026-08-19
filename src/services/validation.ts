/**
 * Fast API key validation with HMAC signature verification.
 *
 * Two-layer validation:
 *   1. validateKeyFormat()  — synchronous, format + HMAC only (no DB).
 *   2. validateKey()        — async, format + HMAC + DB-backed scope lookup.
 *
 * Background: API-key auth previously hardcoded `scopes: ['read','write']`,
 * making admin operations dispatched via API key impossible.  validateKey()
 * now reads the `scopes` field from the api_key row (when present) so admin-
 * scoped keys can authenticate destructive operations.  When the row is
 * missing or has no scopes column we fall through to the legacy default to
 * preserve existing canary auth flows (graceful degradation).
 */

import { createHmac, timingSafeEqual } from 'crypto';
import type { ApiKeyComponents, ValidationResult } from '../types';
import { redactCredential } from './redact';

// Dual-secret (rotation-window) validation. New keys are always SIGNED with the
// CURRENT API_KEY_SECRET (see keyGeneration.ts), but a presented key is ACCEPTED
// if it verifies under the current secret OR any previous secret. Set
// API_KEY_SECRET_PREVIOUS (comma-separated retired secrets) during a rotation
// window: current=new, previous=old keeps old-signed keys valid until every key
// is re-issued, then drop previous. Built ONCE at module load; [current, ...previous],
// deduped, empties filtered. Local-HMAC path only — C6 delegation never uses these.
const SECRET_KEYS: string[] = (() => {
  const current = process.env.API_KEY_SECRET || 'dev-secret-change-in-production';
  const previous = (process.env.API_KEY_SECRET_PREVIOUS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return Array.from(new Set([current, ...previous]));
})();

// C6: issuer-aware validation. A key carries its own issuer endpoint in its
// signed payload (ApiKeyComponents.iss). A spoke cannot recompute the HMAC of a
// hub-issued key (different API_KEY_SECRET), so it validates such a key by
// delegating to the key's OWN issuer instead of requiring a shared secret.
const SELF_ISSUER = process.env.IDENTITY_ENDPOINT || 'https://identity.metabob.com';

function normalizeIssuer(url: string | undefined): string {
  return (url || '').replace(/\/+$/, '').toLowerCase();
}

// Delegation trusts whatever the key claims as `iss`, so it is gated on an
// allowlist. TODO(trusted-issuers): TRUSTED_ISSUERS is the follow-up knob; it
// defaults to [self, HUB_DISCOVERY_URL] so a spoke trusts only its own issuer
// and its hub, never an arbitrary attacker-chosen endpoint.
const TRUSTED_ISSUERS: string[] = (
  process.env.TRUSTED_ISSUERS
    ? process.env.TRUSTED_ISSUERS.split(',')
    : [SELF_ISSUER, process.env.HUB_DISCOVERY_URL || '']
).map((s) => normalizeIssuer(s)).filter(Boolean);

// The keyGeneration DEFAULT issuer (keyGeneration.ts falls back to this exact string
// when IDENTITY_ENDPOINT is unset at mint time) means "locally issued by the default
// identity" — treat it as self, like an empty/legacy issuer, so a substrate validates
// its OWN default-configured keys LOCALLY instead of delegating them to the public
// metabob endpoint (which caused a 401 on discovery registration).
const DEFAULT_ISSUER = 'https://identity.metabob.com';
function isSelfIssuer(iss: string | undefined): boolean {
  const n = normalizeIssuer(iss);
  return n === '' || n === normalizeIssuer(SELF_ISSUER) || n === normalizeIssuer(DEFAULT_ISSUER);
}

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
export function verifySignature(
  components: ApiKeyComponents,
  secrets: string[] = SECRET_KEYS
): boolean {
  const { encodedPayload, signature: providedSignature } = components;

  // Reconstruct what was signed: mb-[base64-payload]
  const finalPayload = `mb-${encodedPayload}`;

  // Constant-time comparison; accept if ANY configured secret reproduces the sig.
  const providedBuffer = Buffer.from(providedSignature);

  for (const secret of secrets) {
    const expectedSignature = createHmac('sha256', secret)
      .update(finalPayload)
      .digest('hex')
      .slice(0, 32); // Truncate to 32 chars for reasonable key length

    const expectedBuffer = Buffer.from(expectedSignature);
    if (providedBuffer.length !== expectedBuffer.length) {
      continue;
    }
    if (timingSafeEqual(providedBuffer, expectedBuffer)) {
      return true;
    }
  }

  return false;
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
 * the api_key table.  Two lookup strategies are attempted to remain forward-
 * compatible across schema variants:
 *   1. Direct record-id lookup (id = api_key:<keyId>)
 *   2. key_prefix field match (current user-vessel schema uses this)
 *
 * If the row does not have a `scopes` field at all (the current schema does
 * not define one yet), null is returned and the caller falls back to the
 * legacy default.
 */
export async function lookupKeyScopes(keyId: string): Promise<string[] | null> {
  if (!keyId) return null;

  try {
    const query = await getQueryFn();

    // SurrealDB 3.x renamed `type::thing` → `type::record`; we avoid the helper
    // entirely and match by `key_id` (HMAC-embedded) or `key_prefix` (operator
    // label). Both fields are indexed (idx_api_key_key_id, idx_api_key_key_prefix).
    const result = await query(
      `SELECT scopes FROM api_key WHERE key_id = $key_id OR key_prefix = $key_id LIMIT 1;`,
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
/**
 * C6: delegate validation of a foreign-issued key to its own issuer.
 *
 * A spoke cannot recompute the HMAC of a hub-issued key (its API_KEY_SECRET
 * differs), so it POSTs the key to the issuer's canonical /v1/keys/validate and
 * trusts that verdict. Mirrors the raw-fetch egress used by services/trace.ts;
 * `iss` is the key's self-described issuer endpoint carried in the key itself,
 * not a discovery capability row, so a direct fetch is the intended path (there
 * is no libp2p egress in identity-vessel to route through).
 */
async function delegateValidation(apiKey: string, iss: string): Promise<ValidationResult> {
  if (!TRUSTED_ISSUERS.includes(normalizeIssuer(iss))) {
    return { valid: false, error: `Untrusted key issuer: ${iss}` };
  }
  try {
    const response = await fetch(`${iss.replace(/\/+$/, '')}/v1/keys/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_key: apiKey }),
    });
    if (!response.ok) {
      return { valid: false, error: `Issuer validation failed (${response.status})` };
    }
    const parsed: any = await response.json();
    // /v1/keys/validate wraps its verdict as { success, data: {...} }.
    const data = parsed?.data ?? parsed;
    if (!data || data.valid !== true) {
      // We POSTed the caller's key to the issuer. If that issuer echoes the
      // key back in its own error string, forwarding it verbatim would leak
      // the credential through OUR response body. Scrub before surfacing.
      const upstream = typeof data?.error === 'string' ? data.error : '';
      return {
        valid: false,
        error: upstream ? redactCredential(upstream, apiKey) : 'Issuer rejected key',
      };
    }
    return {
      valid: true,
      orgId: data.org_id,
      userId: data.user_id,
      keyId: data.key_id,
      scopes: Array.isArray(data.scopes) ? data.scopes : undefined,
    };
  } catch (error) {
    return {
      valid: false,
      // fetch/DNS errors can quote the request; scrub the key out regardless.
      error: redactCredential(
        `Issuer unreachable: ${error instanceof Error ? error.message : String(error)}`,
        apiKey,
      ),
    };
  }
}

export async function validateKey(apiKey: string): Promise<ValidationResult> {
  // LOCAL-FIRST validation (C6): a key the local secret(s) can HMAC-verify is OURS
  // (or a shared-secret, in-identity-group peer) regardless of how its `iss` is
  // labelled — validate it locally. Only a key we CANNOT verify locally is treated
  // as foreign: if its `iss` is a trusted remote issuer, delegate to that issuer;
  // otherwise it is invalid. This ordering is robust to iss/host-form/env-load
  // mismatches (an earlier iss-gated version mis-routed our OWN keys to delegation,
  // which failed as "Untrusted issuer" -> 401 on registration) while still
  // supporting cross-substrate keys via issuer delegation.
  const result = validateKeyFormat(apiKey);

  if (result.valid && result.keyId) {
    const scopes = await lookupKeyScopes(result.keyId);
    return scopes !== null ? { ...result, scopes } : result;
  }

  // Local verification failed — maybe a foreign key signed by a trusted issuer.
  const components = parseApiKey(apiKey);
  if (components && !isSelfIssuer(components.iss)) {
    return delegateValidation(apiKey, components.iss);
  }

  return result;
}
