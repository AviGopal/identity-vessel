/**
 * Identity Vessel - Single source of truth for API key operations
 *
 * This vessel is the authoritative service for:
 * - API key generation (HMAC-based)
 * - API key validation (format + signature + revocation check)
 * - API key revocation (Redis-backed)
 *
 * Other vessels delegate to identity-vessel for all API key operations.
 *
 * API Key Endpoints:
 * - POST /v1/keys/generate    - Generate new API key
 *   Request:  { org_id, user_id, scopes[]?, key_type?: "live"|"test", name?, expires_in_days? }
 *   Response: { api_key, key_id, prefix, expires_at?, metadata }
 *
 * - POST /v1/keys/validate    - Validate API key (direct call)
 *   Request:  { api_key }
 *   Response: { valid, org_id?, user_id?, key_id?, scopes[]?, role?, error? }
 *
 * - POST /v1/keys/revoke      - Revoke an API key
 *   Request:  { key_id } or { api_key }
 *   Response: { revoked: true }
 *
 * Authentication Endpoints:
 * - POST /v1/auth/resolve     - Resolve authentication impulse (JWT or API key)
 * - POST /v1/auth/minibob/signin - MiniBob instance authentication
 * - POST /v2/auth/minibob/signin - MiniBob instance authentication (v2 alias)
 *
 * For account management (login/signup/password change), use user-vessel.
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { resolveAuthentication } from './resolvers/auth';
import { authenticateMiniBobInstance, handleAuthError } from './services/minibob-auth';
import { generateApiKey, generateKeyMetadata } from './services/keyGeneration';
import { validateKeyFormat, parseApiKey } from './services/validation';
import { revokeKey, isKeyRevoked } from './db/redis';
import { config } from './services/config';
import { z } from 'zod';

const app = new Hono();

// Middleware
app.use('*', logger());
app.use('*', cors({
  origin: ['http://localhost:3000', 'http://app.metabob.local', 'http://activity.metabob.local'],
  credentials: true
}));

// ============================================================================
// Public Endpoints
// ============================================================================

// Health check
app.get('/health', (c) => {
  return c.json({
    status: 'ok',
    service: 'identity-vessel',
    version: '0.1.0',
    timestamp: new Date().toISOString()
  });
});

// Vessel capabilities (public metadata)
app.get('/capabilities', (c) => {
  return c.json({
    vessel: {
      id: 'identity-vessel',
      name: 'Identity & Authentication Vessel',
      version: '0.3.0',
      type: 'authentication'
    },
    resolvers: [
      {
        type: 'authentication',
        description: 'Validates API keys (HMAC) and JWT session tokens',
        avgLatency: 2,
        cost: 0.0001
      }
    ],
    endpoints: [
      // API Key Management (canonical source of truth)
      'POST /v1/keys/generate - Generate new API key with HMAC signature',
      'POST /v1/keys/validate - Validate API key (format, signature, revocation)',
      'POST /v1/keys/revoke - Revoke an API key',
      // Authentication
      'POST /v1/auth/resolve - Resolve authentication impulse (JWT or API key)',
      'POST /v1/auth/minibob/signin - MiniBob instance authentication',
      'POST /v2/auth/minibob/signin - MiniBob instance authentication (v2 alias)'
    ],
    notes: [
      'identity-vessel is the SINGLE SOURCE OF TRUTH for API key operations',
      'For user management (login/signup/password): use user-vessel',
      'user-vessel delegates key generation/validation to identity-vessel',
      'Revocation is stored in Redis with 1-year TTL'
    ]
  });
});

// ============================================================================
// Authentication Resolution Endpoint (for other vessels)
// ============================================================================

const resolveSchema = z.object({
  impulse: z.object({
    type: z.literal('authentication'),
    pointer: z.union([
      z.object({
        type: z.literal('apiKey'),
        apiKey: z.string()
      }),
      z.object({
        type: z.literal('session'),
        token: z.string()
      })
    ])
  })
});

app.post('/v1/auth/resolve', async (c) => {
  try {
    const body = await c.req.json();
    const { impulse } = resolveSchema.parse(body);

    const result = await resolveAuthentication(impulse);

    // Return proper HTTP status based on authentication result
    if (!result.authenticated) {
      return c.json({
        success: false,
        error: {
          code: 'AUTHENTICATION_FAILED',
          message: result.reason || 'Authentication failed'
        }
      }, 401);
    }

    return c.json({
      success: true,
      data: result
    });
  } catch (error) {
    return c.json({
      success: false,
      error: {
        code: 'RESOLVE_FAILED',
        message: error instanceof Error ? error.message : 'Unknown error'
      }
    }, 400);
  }
});

// ============================================================================
// MiniBob Instance Authentication (for autonomous vessels)
// ============================================================================

const minibobSigninSchema = z.object({
  instance_id: z.string().min(1),
  api_key: z.string().min(1)
});

app.post('/v1/auth/minibob/signin', async (c) => {
  try {
    const body = await c.req.json();
    const { instance_id, api_key } = minibobSigninSchema.parse(body);

    const result = await authenticateMiniBobInstance(instance_id, api_key);

    console.log('[MiniBob Signin] Success:', {
      instance_id,
      org_id: result.org_id,
    });

    return c.json({
      success: true,
      token: result.token,
      org_id: result.org_id,
    });
  } catch (error) {
    console.error('[MiniBob Signin] Error:', error);

    const { statusCode, message } = handleAuthError(error);

    return c.json(
      {
        success: false,
        error: message
      },
      statusCode as 401 | 500
    );
  }
});

// v2 API alias for consistency with MiniBob bootstrap client
app.post('/v2/auth/minibob/signin', async (c) => {
  try {
    const body = await c.req.json();
    const { instance_id, api_key } = minibobSigninSchema.parse(body);

    const result = await authenticateMiniBobInstance(instance_id, api_key);

    console.log('[MiniBob Signin v2] Success:', {
      instance_id,
      org_id: result.org_id,
      project_id: result.project_id,
    });

    // Return response with org_id and project_id (if available)
    return c.json({
      success: true,
      token: result.token,
      org_id: result.org_id,
      project_id: result.project_id,
    });
  } catch (error) {
    console.error('[MiniBob Signin v2] Error:', error);

    const { statusCode, message } = handleAuthError(error);

    return c.json(
      {
        success: false,
        error: message
      },
      statusCode as 401 | 500
    );
  }
});

// ============================================================================
// API Key Generation Endpoint (canonical source of truth)
// ============================================================================

const generateKeySchema = z.object({
  org_id: z.string().min(1),
  user_id: z.string().min(1),
  name: z.string().optional(),
  scopes: z.array(z.string()).optional(),
  expires_in_days: z.number().positive().optional(),
});

/**
 * POST /v1/keys/generate
 * Generate a new API key with HMAC signature.
 * This is the canonical endpoint - all services should call this.
 *
 * The generated key is ONLY returned once. The caller is responsible
 * for storing key metadata in their own database.
 */
app.post('/v1/keys/generate', async (c) => {
  try {
    const body = await c.req.json();
    const { org_id, user_id, name, scopes, expires_in_days } = generateKeySchema.parse(body);

    // Generate the API key
    const keyResult = generateApiKey(org_id, user_id, {
      name,
      scopes,
      expiresInDays: expires_in_days,
    });

    // Generate metadata for database storage (caller stores this)
    const metadata = generateKeyMetadata(
      org_id,
      user_id,
      keyResult.keyId,
      keyResult.prefix,
      { name, scopes, expiresInDays: expires_in_days }
    );

    console.log('[KeyGeneration] Generated key:', {
      org_id,
      user_id,
      key_id: keyResult.keyId,
      prefix: keyResult.prefix,
    });

    return c.json({
      success: true,
      data: {
        key: keyResult.key,           // Base64-encoded HMAC key (only shown once!)
        key_id: keyResult.keyId,      // Unique key identifier
        prefix: keyResult.prefix,     // mb_live or mb_test
        expires_at: keyResult.expiresAt,
        metadata,                      // For caller to store in their database
      },
    });
  } catch (error) {
    console.error('[KeyGeneration] Error:', error);

    return c.json({
      success: false,
      error: {
        code: 'KEY_GENERATION_FAILED',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
    }, 400);
  }
});

// ============================================================================
// API Key Validation Endpoint (canonical source of truth)
// ============================================================================

const validateKeySchema = z.object({
  api_key: z.string().min(1),
});

/**
 * POST /v1/keys/validate
 * Validate an API key - checks format, HMAC signature, and revocation status.
 * This is the canonical validation endpoint - all services should call this.
 *
 * Request:  { api_key: string }
 * Response: { valid: boolean, org_id?, user_id?, key_id?, scopes?, role?, error? }
 */
app.post('/v1/keys/validate', async (c) => {
  try {
    const body = await c.req.json();
    const { api_key } = validateKeySchema.parse(body);

    // Step 1: Validate format and HMAC signature (fast path - no network)
    const validation = validateKeyFormat(api_key);

    if (!validation.valid) {
      return c.json({
        success: true,
        data: {
          valid: false,
          error: validation.error || 'Invalid API key format or signature',
        },
      });
    }

    // Step 2: Check revocation in Redis
    const revoked = await isKeyRevoked(validation.keyId!);

    if (revoked) {
      return c.json({
        success: true,
        data: {
          valid: false,
          error: 'API key has been revoked',
        },
      });
    }

    // Key is valid
    console.log('[KeyValidation] Key validated:', {
      key_id: validation.keyId,
      org_id: validation.orgId,
    });

    return c.json({
      success: true,
      data: {
        valid: true,
        org_id: validation.orgId,
        user_id: validation.userId,
        key_id: validation.keyId,
        scopes: validation.scopes || ['read', 'write'],
        role: 'user', // Default role - caller can override based on their DB
      },
    });
  } catch (error) {
    console.error('[KeyValidation] Error:', error);

    return c.json({
      success: false,
      error: {
        code: 'VALIDATION_FAILED',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
    }, 400);
  }
});

// ============================================================================
// API Key Revocation Endpoint (canonical source of truth)
// ============================================================================

const revokeKeySchema = z.object({
  // Either key_id or api_key must be provided
  key_id: z.string().optional(),
  api_key: z.string().optional(),
}).refine(
  (data) => data.key_id || data.api_key,
  { message: 'Either key_id or api_key must be provided' }
);

/**
 * POST /v1/keys/revoke
 * Revoke an API key - marks it as invalid in Redis.
 * The caller is responsible for updating their own database.
 *
 * Request:  { key_id: string } OR { api_key: string }
 * Response: { revoked: true }
 *
 * Note: Revocation is stored in Redis with 1-year TTL.
 * Even if caller's database already marks key as inactive,
 * this ensures fast rejection at the identity-vessel level.
 */
app.post('/v1/keys/revoke', async (c) => {
  try {
    const body = await c.req.json();
    const { key_id, api_key } = revokeKeySchema.parse(body);

    let keyIdToRevoke: string;

    if (key_id) {
      // Direct key_id provided
      keyIdToRevoke = key_id;
    } else if (api_key) {
      // Extract key_id from api_key
      const components = parseApiKey(api_key);
      if (!components) {
        return c.json({
          success: false,
          error: {
            code: 'INVALID_API_KEY',
            message: 'Could not parse API key to extract key_id',
          },
        }, 400);
      }
      keyIdToRevoke = components.keyId;
    } else {
      return c.json({
        success: false,
        error: {
          code: 'MISSING_PARAMETER',
          message: 'Either key_id or api_key must be provided',
        },
      }, 400);
    }

    // Revoke in Redis (1 year TTL)
    await revokeKey(keyIdToRevoke);

    console.log('[KeyRevocation] Key revoked:', {
      key_id: keyIdToRevoke,
    });

    return c.json({
      success: true,
      data: {
        revoked: true,
        key_id: keyIdToRevoke,
      },
    });
  } catch (error) {
    console.error('[KeyRevocation] Error:', error);

    return c.json({
      success: false,
      error: {
        code: 'REVOCATION_FAILED',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
    }, 500);
  }
});

// ============================================================================
// Architecture Notes
// ============================================================================
//
// identity-vessel is the SINGLE SOURCE OF TRUTH for API key operations:
// - /v1/keys/generate: Create new HMAC-signed API keys
// - /v1/keys/validate: Validate keys (format, signature, revocation)
// - /v1/keys/revoke: Mark keys as revoked in Redis
//
// user-vessel handles:
// - User management (login/signup/password change)
// - API key metadata storage (which keys exist, who owns them)
// - API key listing (GET /v2/api-keys)
// - Delegates actual key operations to identity-vessel
//
// The flow for creating an API key:
// 1. User calls user-vessel POST /v2/api-keys
// 2. user-vessel calls identity-vessel POST /v1/keys/generate
// 3. identity-vessel generates HMAC-signed key, returns it
// 4. user-vessel stores metadata in SurrealDB, returns key to user
//
// The flow for validating an API key:
// 1. Request arrives at any service with Authorization header
// 2. Service calls identity-vessel POST /v1/keys/validate
// 3. identity-vessel checks HMAC signature and Redis revocation
// 4. Service uses returned org_id/user_id/scopes for authorization
//
// The flow for revoking an API key:
// 1. User calls user-vessel DELETE /v2/api-keys/:id
// 2. user-vessel marks key as inactive in SurrealDB
// 3. user-vessel calls identity-vessel POST /v1/keys/revoke
// 4. identity-vessel marks key in Redis for fast rejection
// ============================================================================

// ============================================================================
// Start Server
// ============================================================================

console.log('[IdentityVessel] Starting server on port ' + config.port);

export default {
  port: config.port,
  fetch: app.fetch
};
