/**
 * Authentication resolver - implements impulse resolution pattern
 * Other vessels can call this to resolve authentication impulses
 */

import type { AuthenticationImpulse, AuthenticationResult } from '../types';
import { validateKeyFormat } from '../services/validation';
import { isKeyRevoked } from '../db/redis';
import { traceAuthentication } from '../services/trace';

/**
 * Resolve an authentication impulse (internal implementation)
 * This is how other vessels delegate authentication to this vessel
 */
async function _resolveAuthentication(
  impulse: AuthenticationImpulse
): Promise<AuthenticationResult> {
  const { apiKey } = impulse.pointer;

  // Validate format and signature
  const validation = validateKeyFormat(apiKey);

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

  // Authentication successful
  return {
    authenticated: true,
    orgId: validation.orgId,
    userId: validation.userId,
    keyId: validation.keyId,
    scopes: validation.scopes || ['read', 'write']
  };
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
