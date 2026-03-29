/**
 * Authentication resolver - implements impulse resolution pattern
 * Other vessels can call this to resolve authentication impulses
 */

import type { AuthenticationImpulse, AuthenticationResult } from '../types';
import { validateKeyFormat } from '../services/validation';
import { isKeyRevoked } from '../db/redis';
import { traceAuthentication } from '../services/trace';
import { verify } from 'hono/jwt';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';

/**
 * Resolve JWT session token
 */
async function resolveJWT(token: string): Promise<AuthenticationResult> {
  try {
    const payload = await verify(token, JWT_SECRET);

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
    type: 'api_key',
    scopes: validation.scopes || ['read', 'write']
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
  const token = impulse.pointer.apiKey || impulse.pointer.token;

  if (!token) {
    return {
      authenticated: false,
      reason: 'No authentication token provided'
    };
  }

  // Detect authentication type
  if (token.startsWith('eyJ')) {
    // JWT session token (JWTs start with eyJ when base64-encoded)
    return await resolveJWT(token);
  } else {
    // API key (HMAC-based)
    return await resolveAPIKey(token);
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
