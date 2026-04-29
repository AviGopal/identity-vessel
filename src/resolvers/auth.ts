/**
 * Authentication resolver - implements impulse resolution pattern
 * Other vessels can call this to resolve authentication impulses
 *
 * Account-id enrichment (2026-04-27):
 *   After validating an API key or JWT we OPTIONALLY query user-vessel for
 *   the caller's account memberships and pick a default account, then emit
 *   an `accountId` field on the result.  user-vessel is the source of truth
 *   for user→account mappings; identity-vessel does not cache them.
 *
 *   Failures are non-fatal — `accountId` is simply omitted, and downstream
 *   tenant helpers (user-vessel/activity-api) fall back to deriving it from
 *   `orgId` ("organizations:<x>" → "accounts:<x>").  This is the prerequisite
 *   for activity-api adopting `$token.account_id` in PERMISSIONS clauses.
 */

import type { AuthenticationImpulse, AuthenticationResult } from '../types';
import { validateKey } from '../services/validation';
import { isKeyRevoked } from '../db/redis';
import { traceAuthentication } from '../services/trace';
import { verify } from 'hono/jwt';
import {
  UserVesselClient,
  pickDefaultAccount,
  normalizeAccountId,
} from '../services/user-vessel-client';
import { config } from '../services/config';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';

// Lazy-initialized singleton.  Tests can substitute via `setUserVesselClient`.
let userVesselClient: UserVesselClient | null = null;
function getUserVesselClient(): UserVesselClient | null {
  if (!config.userVessel.enabled) return null;
  if (!userVesselClient) {
    userVesselClient = new UserVesselClient({
      endpoint: config.userVessel.endpoint,
      timeoutMs: config.userVessel.timeoutMs,
    });
  }
  return userVesselClient;
}

/** Test-only override.  Pass null to reset to the default client. */
export function setUserVesselClient(client: UserVesselClient | null): void {
  userVesselClient = client;
}

/**
 * Try to enrich an authenticated result with an `accountId` claim by
 * querying user-vessel.  Returns the input unmodified on any failure
 * (network, missing membership, user-vessel disabled).  Never throws.
 */
async function enrichWithAccountId(
  result: AuthenticationResult,
  authHeader: string,
): Promise<AuthenticationResult> {
  if (!result.authenticated || !result.userId) return result;

  const client = getUserVesselClient();
  if (!client) return result;

  try {
    const memberships = await client.queryUserAccounts(result.userId, authHeader);
    if (!memberships || memberships.length === 0) {
      // No membership data → leave accountId undefined; caller falls back to
      // deriving from orgId.  Single-line warn for migration monitoring.
      console.warn('[auth] account_id lookup returned empty', {
        user_id: result.userId,
      });
      return result;
    }

    const chosen = pickDefaultAccount(memberships);
    if (!chosen) return result;

    return { ...result, accountId: normalizeAccountId(chosen.account_id) };
  } catch (err) {
    // Defensive: client already swallows errors and returns null.  This catch
    // is belt-and-braces in case a future change throws.
    const message = err instanceof Error ? err.message : 'unknown error';
    console.warn('[auth] account_id enrichment failed', { err: message });
    return result;
  }
}

/**
 * Resolve JWT session token
 */
async function resolveJWT(token: string): Promise<AuthenticationResult> {
  try {
    const payload = await verify(token, JWT_SECRET, "HS256") as any;

    return {
      authenticated: true,
      orgId: payload.orgId as string,
      userId: payload.userId as string,
      type: 'session',
      scopes: ['read', 'write'] // Sessions get full access
    };
  } catch (error) {
    return {
      authenticated: false,
      reason: 'Invalid or expired JWT token'
    };
  }
}

/**
 * Resolve API key
 */
async function resolveAPIKey(apiKey: string): Promise<AuthenticationResult> {
  // Validate format, signature, and look up DB-backed scopes (F-NN-I).
  // validateKey returns scopes from the api_key row when present; otherwise
  // scopes is left undefined and we fall back to the legacy default below.
  const validation = await validateKey(apiKey);

  if (!validation.valid) {
    return {
      authenticated: false,
      reason: validation.error || 'Invalid API key'
    };
  }

  // Check revocation
  const revoked = await isKeyRevoked(validation.keyId!);

  if (revoked) {
    return {
      authenticated: false,
      reason: 'API key has been revoked'
    };
  }

  // Authentication successful.  Use ?? rather than || so that an explicit
  // empty-array scopes value from the DB does not silently inherit defaults
  // (`||` would, `??` won't — and lookupKeyScopes already returns null for
  // empty arrays, keeping the default-fallback contract intact).
  return {
    authenticated: true,
    orgId: validation.orgId,
    userId: validation.userId,
    keyId: validation.keyId,
    type: 'api_key',
    scopes: validation.scopes ?? ['read', 'write']
  };
}

/**
 * Resolve an authentication impulse (internal implementation)
 * This is how other vessels delegate authentication to this vessel
 * Handles both JWT session tokens and API keys
 */
async function _resolveAuthentication(
  impulse: AuthenticationImpulse
): Promise<AuthenticationResult> {
  // Use explicit pointer type instead of heuristic detection
  const pointerType = impulse.pointer.type;

  if (pointerType === 'session') {
    const token = impulse.pointer.token;
    if (!token) {
      return {
        authenticated: false,
        reason: 'No session token provided'
      };
    }
    const result = await resolveJWT(token);
    return enrichWithAccountId(result, `Bearer ${token}`);
  } else if (pointerType === 'apiKey') {
    const apiKey = impulse.pointer.apiKey;
    if (!apiKey) {
      return {
        authenticated: false,
        reason: 'No API key provided'
      };
    }
    const result = await resolveAPIKey(apiKey);
    return enrichWithAccountId(result, `ApiKey ${apiKey}`);
  } else {
    return {
      authenticated: false,
      reason: `Unknown authentication type: ${pointerType}`
    };
  }
}

/**
 * Resolve an authentication impulse with trace collection
 */
export async function resolveAuthentication(
  impulse: AuthenticationImpulse
): Promise<AuthenticationResult> {
  return traceAuthentication(() => _resolveAuthentication(impulse));
}

/**
 * Register this resolver with the vessel registry
 */
export const authenticationResolver = {
  type: 'authentication',
  resolve: resolveAuthentication,
  description: 'Resolves API key authentication impulses',
  cost: 0.0001, // Very cheap - just HMAC + Redis lookup
  avgLatency: 2 // ~2ms average
};
