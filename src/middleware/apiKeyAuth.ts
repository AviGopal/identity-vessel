/**
 * Fast API key authentication middleware
 * Performance: ~1-2ms average (format check + Redis + HMAC)
 */

import type { Context, Next } from 'hono';
import { validateKeyFormat } from '../services/validation';
import { isKeyRevoked } from '../db/redis';
import type { AuthContext } from '../types';

/**
 * API key authentication middleware
 * Validates format, signature, and revocation status
 *
 * Supports two Authorization header formats:
 * - ApiKey <key>: Explicit API key format (preferred)
 * - Bearer <key>: Legacy format (for backward compatibility)
 */
export async function apiKeyAuthMiddleware(c: Context, next: Next) {
  const authHeader = c.req.header('Authorization');

  // Fast path 1: Missing header (~1μs)
  if (!authHeader) {
    return c.json({
      error: {
        code: 'MISSING_AUTH_HEADER',
        message: 'Missing Authorization header',
        suggestion: 'Include "Authorization: ApiKey <api_key>" header'
      }
    }, 401);
  }

  // Parse Authorization header - support both ApiKey and Bearer prefixes
  let apiKey: string;
  if (authHeader.startsWith('ApiKey ')) {
    apiKey = authHeader.slice(7); // Remove 'ApiKey '
  } else if (authHeader.startsWith('Bearer ')) {
    // Legacy support - Bearer prefix for backward compatibility
    apiKey = authHeader.slice(7); // Remove 'Bearer '
  } else {
    return c.json({
      error: {
        code: 'INVALID_AUTH_SCHEME',
        message: 'Invalid Authorization scheme',
        suggestion: 'Use "Authorization: ApiKey <api_key>" format'
      }
    }, 401);
  }
  
  // Fast path 2: Validate format and HMAC signature (~10μs)
  const validation = validateKeyFormat(apiKey);
  
  if (!validation.valid) {
    return c.json({
      error: {
        code: 'INVALID_API_KEY',
        message: validation.error || 'Invalid API key',
        suggestion: 'Check your API key format and try again'
      }
    }, 401);
  }
  
  // Fast path 3: Check revocation cache (~1ms Redis lookup)
  const revoked = await isKeyRevoked(validation.keyId!);
  
  if (revoked) {
    return c.json({
      error: {
        code: 'REVOKED_API_KEY',
        message: 'API key has been revoked',
        suggestion: 'Generate a new API key from the dashboard'
      }
    }, 401);
  }
  
  // Valid key - populate auth context
  const authContext: AuthContext = {
    orgId: validation.orgId!,
    userId: validation.userId!,
    keyId: validation.keyId!,
    type: 'api_key',
    scopes: validation.scopes || ['read', 'write']
  };
  
  c.set('auth', authContext);
  
  await next();
}

/**
 * Optional middleware - require specific scopes
 */
export function requireScopes(...requiredScopes: string[]) {
  return async (c: Context, next: Next) => {
    const auth = c.get('auth') as AuthContext | undefined;
    
    if (!auth) {
      return c.json({
        error: {
          code: 'NOT_AUTHENTICATED',
          message: 'Authentication required'
        }
      }, 401);
    }
    
    const hasAllScopes = requiredScopes.every(scope => 
      auth.scopes.includes(scope)
    );
    
    if (!hasAllScopes) {
      return c.json({
        error: {
          code: 'INSUFFICIENT_PERMISSIONS',
          message: 'API key does not have required scopes',
          required: requiredScopes,
          actual: auth.scopes
        }
      }, 403);
    }
    
    await next();
  };
}
