/**
 * Identity Vessel - Single source of truth for authentication operations
 *
 * This vessel is the authoritative service for:
 * - JWT token generation and validation (Hono JWT, HS256)
 * - Password hashing and verification (Argon2id via Bun)
 * - API key generation (HMAC-based)
 * - API key validation (format + signature + revocation check)
 * - API key revocation (Redis-backed)
 *
 * Other vessels delegate to identity-vessel for ALL authentication operations.
 *
 * JWT Endpoints:
 * - POST /v1/jwt/generate     - Generate JWT token
 *   Request:  { user_id, org_id, role, project_ids[]?, expires_in_seconds? }
 *   Response: { token, expires_at, issued_at }
 *
 * - POST /v1/jwt/verify       - Verify JWT token
 *   Request:  { token }
 *   Response: { valid, user_id?, org_id?, role?, project_ids[]?, exp?, iat?, error? }
 *
 * Password Endpoints:
 * - POST /v1/auth/password/hash    - Hash a password
 *   Request:  { password }
 *   Response: { hash }
 *
 * - POST /v1/auth/password/verify  - Verify a password against hash
 *   Request:  { password, hash }
 *   Response: { valid }
 *
 * - POST /v1/auth/password/validate - Validate password strength
 *   Request:  { password }
 *   Response: { valid, errors[], score }
 *
 * Sign-in Endpoints (email+password):
 * - POST /v1/auth/login       - Email + password sign-in → JWT
 *   Request:  { email, password }
 *   Response: { token, user_id, org_id, role, account_id?, expires_at }
 *
 * - POST /v1/auth/signup      - Create user + org → JWT
 *   Request:  { email, password, name?, org_name?, accept_invitation_token? }
 *   Response: { token, user_id, org_id, role, account_id?, expires_at }
 *
 * API Key Endpoints:
 * - POST /v1/keys/generate    - Generate new API key (no DB persistence)
 *   Request:  { org_id, user_id, scopes[]?, key_type?: "live"|"test", name?, expires_in_days? }
 *   Response: { api_key, key_id, prefix, expires_at?, metadata }
 *
 * - POST /v1/keys/issue       - Mint new API key AND persist row (admin-only)
 *   Request:  { user_id, org_id, scopes[]?, expires_in_days?, name? }
 *   Response: { key, key_id, expires_at? }
 *
 * - POST /v1/keys/validate    - Validate API key (direct call)
 *   Request:  { api_key }
 *   Response: { valid, org_id?, user_id?, key_id?, scopes[]?, role?, error? }
 *
 * - POST /v1/keys/revoke      - Revoke an API key
 *   Request:  { key_id } or { api_key }
 *   Response: { revoked: true }
 *
 * Authentication Resolution:
 * - POST /v1/auth/resolve     - Resolve authentication impulse (JWT or API key)
 * - POST /v1/auth/minibob/signin - DEPRECATED (returns 410)
 * - POST /v2/auth/minibob/signin - DEPRECATED (returns 410)
 *
 * For account/org/member management, use user-vessel (which delegates auth to this vessel).
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { resolveAuthentication } from './resolvers/auth';
import type { AuthenticationImpulse } from './types';
import { generateApiKey, generateKeyMetadata } from './services/keyGeneration';
import { validateKeyFormat, validateKey, parseApiKey } from './services/validation';
import { revokeKey, isKeyRevoked } from './db/redis';
import { config } from './services/config';
import { issueApiKey } from './resolvers/issue-key';
import { loginWithPassword, signupWithPassword } from './resolvers/login';
import { z } from 'zod';
import { generateToken, verifyToken, getSecretInfo } from './services/jwt';
import { hashPassword, verifyPassword, validatePassword } from './services/password';
import { createRateLimitMiddleware } from './middleware/ratelimit';

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

// Health check with discovery status
app.get('/health', (c) => {
  const healthStatus: any = {
    status: 'ok',
    service: 'identity-vessel',
    version: '0.2.0',
    timestamp: new Date().toISOString(),
    checks: {
      discovery: { status: 'unknown', registered: false }
    }
  };

  // Check Discovery registration status
  const { discoveryClient } = require('./services/discovery-client');
  if (discoveryClient) {
    const isRunning = discoveryClient.isRunning;
    const lastHeartbeat = discoveryClient.lastHeartbeat;

    healthStatus.checks.discovery = {
      status: isRunning ? 'healthy' : 'pending',
      registered: isRunning,
      lastHeartbeat: lastHeartbeat ? lastHeartbeat.toISOString() : null
    };
  } else {
    healthStatus.checks.discovery = {
      status: 'disabled',
      registered: false
    };
  }

  return c.json(healthStatus);
});

// Vessel capabilities (public metadata)
app.get('/capabilities', (c) => {
  return c.json({
    vessel: {
      id: 'identity-vessel',
      name: 'Identity & Authentication Vessel',
      version: '0.5.0',
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
      // JWT Operations (canonical source of truth)
      'POST /v1/jwt/generate - Generate JWT token with claims',
      'POST /v1/jwt/verify - Verify JWT token and extract claims',
      // Password Operations (canonical source of truth)
      'POST /v1/auth/password/hash - Hash password with Argon2id',
      'POST /v1/auth/password/verify - Verify password against hash',
      'POST /v1/auth/password/validate - Validate password strength',
      // Sign-in flow (email+password)
      'POST /v1/auth/login - Email+password sign-in → JWT',
      'POST /v1/auth/signup - Create user+org → JWT',
      // API Key Management (canonical source of truth)
      'POST /v1/keys/generate - Generate new API key with HMAC signature',
      'POST /v1/keys/issue - Mint new API key + persist row (admin-only)',
      'POST /v1/keys/validate - Validate API key (format, signature, revocation)',
      'POST /v1/keys/revoke - Revoke an API key',
      // Authentication Resolution
      'POST /v1/auth/resolve - Resolve authentication impulse (JWT or API key)',
      'POST /v1/auth/minibob/signin - DEPRECATED (returns 410)',
      'POST /v2/auth/minibob/signin - DEPRECATED (returns 410)'
    ],
    notes: [
      'identity-vessel is the SINGLE SOURCE OF TRUTH for ALL authentication operations',
      'JWT: Uses hono/jwt with HS256 algorithm',
      'Password: Uses Argon2id via Bun.password (memory-hard, side-channel resistant)',
      'API Keys: HMAC-based generation with Redis-backed revocation',
      'user-vessel handles org/member/api-key DATA, delegates auth to identity-vessel'
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

/**
 * POST /v1/auth/resolve
 *
 * Two request forms are accepted:
 *
 * 1. Nested impulse form (legacy / activity-api):
 *      Body: { impulse: { type: 'authentication', pointer: { type, apiKey|token } } }
 *      Response: { success: true, data: AuthenticationResult }
 *      where AuthenticationResult uses camelCase keys (orgId, userId, accountId).
 *
 * 2. Flat header form (user-vessel / dashboard):
 *      Header: Authorization: ApiKey <key>  OR  Authorization: Bearer <jwt>
 *      Body:   {} or empty
 *      Response: { valid: true, user_id, org_id, account_id?, role }
 *      Snake-case keys to match user-vessel's `IdentityClient` contract.
 *
 * The `account_id` claim is populated when user-vessel returns membership
 * data for the resolved user.  If user-vessel is unreachable or the user has
 * no memberships, `account_id` is omitted and downstream services derive it
 * from `org_id`.
 */
app.post('/v1/auth/resolve', createRateLimitMiddleware('auth_resolve', 20), async (c) => {
  try {
    // Read body defensively — flat-form callers may send `{}` or no body.
    let body: any = {};
    try {
      body = await c.req.json();
    } catch {
      body = {};
    }

    // Branch 1: nested impulse form — body has an `impulse` field.
    if (body && typeof body === 'object' && body.impulse) {
      const { impulse } = resolveSchema.parse(body);
      const result = await resolveAuthentication(impulse);

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
    }

    // Branch 2: flat header form — read Authorization header.
    const authHeader = c.req.header('Authorization');
    if (!authHeader) {
      return c.json({
        success: false,
        error: {
          code: 'MISSING_AUTH_HEADER',
          message: 'Provide either { impulse } body or Authorization header',
        },
      }, 400);
    }

    let impulseFromHeader: AuthenticationImpulse;
    if (authHeader.startsWith('ApiKey ')) {
      impulseFromHeader = {
        type: 'authentication',
        pointer: { type: 'apiKey', apiKey: authHeader.slice('ApiKey '.length) },
      };
    } else if (authHeader.startsWith('Bearer ')) {
      impulseFromHeader = {
        type: 'authentication',
        pointer: { type: 'session', token: authHeader.slice('Bearer '.length) },
      };
    } else {
      return c.json({
        success: false,
        error: {
          code: 'INVALID_AUTH_SCHEME',
          message: 'Authorization must start with "ApiKey " or "Bearer "',
        },
      }, 400);
    }

    const result = await resolveAuthentication(impulseFromHeader);
    if (!result.authenticated) {
      return c.json({
        valid: false,
        error: result.reason || 'Authentication failed',
      }, 401);
    }

    // Flat snake-case response — matches user-vessel's IdentityClient contract.
    // role is unknown to identity-vessel (user-vessel owns roles); default to
    // `member` so the consumer's required-role check has a sane baseline.
    return c.json({
      valid: true,
      user_id: result.userId,
      org_id: result.orgId,
      account_id: result.accountId,
      role: 'member',
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
// JWT Token Generation and Verification (canonical source of truth)
// ============================================================================

const generateJWTSchema = z.object({
  user_id: z.string().min(1),
  org_id: z.string().min(1),
  role: z.enum(['admin', 'member', 'viewer']),
  project_ids: z.array(z.string()).optional(),
  expires_in_seconds: z.number().positive().optional(),
});

/**
 * POST /v1/jwt/generate
 * Generate a JWT token with claims.
 * This is the canonical endpoint - all services should call this.
 *
 * Request:  { user_id, org_id, role, project_ids[]?, expires_in_seconds? }
 * Response: { token, expires_at, issued_at }
 */
app.post('/v1/jwt/generate', async (c) => {
  try {
    const body = await c.req.json();
    const options = generateJWTSchema.parse(body);

    const result = await generateToken(options);

    console.log('[JWT] Token generated:', {
      user_id: options.user_id,
      org_id: options.org_id,
      role: options.role,
      expires_at: result.expires_at,
    });

    return c.json({
      success: true,
      data: result,
    });
  } catch (error) {
    console.error('[JWT] Generation error:', error);

    return c.json({
      success: false,
      error: {
        code: 'JWT_GENERATION_FAILED',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
    }, 400);
  }
});

const verifyJWTSchema = z.object({
  token: z.string().min(1),
});

/**
 * POST /v1/jwt/verify
 * Verify a JWT token and extract claims.
 * This is the canonical endpoint - all services should call this.
 *
 * Request:  { token }
 * Response: { valid, user_id?, org_id?, role?, project_ids[]?, exp?, iat?, error? }
 */
app.post('/v1/jwt/verify', async (c) => {
  try {
    const body = await c.req.json();
    const { token } = verifyJWTSchema.parse(body);

    const result = await verifyToken(token);

    if (!result.valid) {
      console.log('[JWT] Token verification failed:', { error: result.error });

      return c.json({
        success: true,
        data: {
          valid: false,
          error: result.error,
        },
      });
    }

    console.log('[JWT] Token verified:', {
      user_id: result.user_id,
      org_id: result.org_id,
    });

    return c.json({
      success: true,
      data: result,
    });
  } catch (error) {
    console.error('[JWT] Verification error:', error);

    return c.json({
      success: false,
      error: {
        code: 'JWT_VERIFICATION_FAILED',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
    }, 400);
  }
});

// ============================================================================
// Password Hashing and Verification (canonical source of truth)
// ============================================================================

const hashPasswordSchema = z.object({
  password: z.string().min(1),
});

/**
 * POST /v1/auth/password/hash
 * Hash a password using Argon2id.
 * This is the canonical endpoint - all services should call this.
 *
 * Request:  { password }
 * Response: { hash }
 */
app.post('/v1/auth/password/hash', async (c) => {
  try {
    const body = await c.req.json();
    const { password } = hashPasswordSchema.parse(body);

    const hash = await hashPassword(password);

    console.log('[Password] Password hashed');

    return c.json({
      success: true,
      data: {
        hash,
      },
    });
  } catch (error) {
    console.error('[Password] Hashing error:', error);

    return c.json({
      success: false,
      error: {
        code: 'PASSWORD_HASH_FAILED',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
    }, 400);
  }
});

const verifyPasswordSchema = z.object({
  password: z.string().min(1),
  hash: z.string().min(1),
});

/**
 * POST /v1/auth/password/verify
 * Verify a password against a hash.
 * This is the canonical endpoint - all services should call this.
 *
 * Request:  { password, hash }
 * Response: { valid }
 */
app.post('/v1/auth/password/verify', createRateLimitMiddleware('password_verify', 5), async (c) => {
  try {
    const body = await c.req.json();
    const { password, hash } = verifyPasswordSchema.parse(body);

    const valid = await verifyPassword(password, hash);

    console.log('[Password] Password verification:', { valid });

    return c.json({
      success: true,
      data: {
        valid,
      },
    });
  } catch (error) {
    console.error('[Password] Verification error:', error);

    return c.json({
      success: false,
      error: {
        code: 'PASSWORD_VERIFY_FAILED',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
    }, 400);
  }
});

const validatePasswordSchema = z.object({
  password: z.string(),
});

/**
 * POST /v1/auth/password/validate
 * Validate password strength.
 * This is the canonical endpoint - all services should call this.
 *
 * Request:  { password }
 * Response: { valid, errors[], score }
 */
app.post('/v1/auth/password/validate', async (c) => {
  try {
    const body = await c.req.json();
    const { password } = validatePasswordSchema.parse(body);

    const result = validatePassword(password);

    console.log('[Password] Password validation:', { valid: result.valid, score: result.score });

    return c.json({
      success: true,
      data: result,
    });
  } catch (error) {
    console.error('[Password] Validation error:', error);

    return c.json({
      success: false,
      error: {
        code: 'PASSWORD_VALIDATE_FAILED',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
    }, 400);
  }
});

// ============================================================================
// Email + Password Sign-in (email+password)
// ============================================================================
//
// POST /v1/auth/login   { email, password }
//   200 → { token, user_id, org_id, role, account_id?, expires_at }
//   401 invalid_credentials | 400 invalid_input | 500 db/jwt
//
// POST /v1/auth/signup  { email, password, name?, org_name?, accept_invitation_token? }
//   200 → same shape as login
//   400 invalid_input | weak_password | needs_invitation_or_org
//   409 email_taken | org name taken | 500 db/jwt | 501 invitation deferred
//
// Constant-time on missing user — see resolvers/login.ts.

app.post('/v1/auth/login', createRateLimitMiddleware('auth_login', 10), async (c) => {
  let body: unknown = {};
  try { body = await c.req.json(); } catch { body = {}; }
  const result = await loginWithPassword(body);
  return c.json(result.body, result.status as any);
});

app.post('/v1/auth/signup', createRateLimitMiddleware('auth_signup', 5), async (c) => {
  let body: unknown = {};
  try { body = await c.req.json(); } catch { body = {}; }
  const result = await signupWithPassword(body);
  return c.json(result.body, result.status as any);
});

// GET /v1/auth/me — return user record + JWT claims for a Bearer token.
//
// Used by the cloud-dashboard's restoreSession flow on page reload to verify
// the persisted token is still valid AND hydrate the User UI (email, name)
// from the source of truth instead of trusting stale sessionStorage. Reuses
// `resolveAuthentication` for JWT validation, then SELECTs the users row for
// email/name. Response shape matches LoginResponse.user so the dashboard
// can store it directly.
app.get('/v1/auth/me', async (c) => {
  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ error: 'missing_bearer_token' }, 401);
  }
  const token = authHeader.slice('Bearer '.length);
  const result = await resolveAuthentication({
    pointer: { type: 'session', token },
  } as AuthenticationImpulse);
  if (!result.authenticated || !result.userId) {
    return c.json({ error: 'invalid_token', reason: result.reason }, 401);
  }

  // Hydrate email + name from the users row. Errors are non-fatal — fall
  // through to the JWT-only response so the UI still renders post-reload.
  let email = '';
  let name = '';
  try {
    const { query } = await import('./db/surrealdb');
    const rows = await query(
      'SELECT email, name FROM users WHERE <string>id = $user_id LIMIT 1;',
      { user_id: result.userId },
    );
    const row = Array.isArray(rows) && Array.isArray(rows[0]) ? rows[0][0] : (rows as any)?.[0];
    if (row && typeof row === 'object') {
      email = typeof row.email === 'string' ? row.email : '';
      name = typeof row.name === 'string' ? row.name : '';
    }
  } catch (err) {
    console.warn('[auth/me] users lookup failed', err instanceof Error ? err.message : err);
  }

  return c.json({
    id: result.userId,
    email,
    name,
    org_id: result.orgId ?? '',
    role: 'member',
    ...(result.accountId ? { account_id: result.accountId } : {}),
  });
});

// ============================================================================
// MiniBob Instance Authentication - DEPRECATED
// ============================================================================

/**
 * POST /v1/auth/minibob/signin - DEPRECATED
 *
 * This endpoint was removed on 2026-04-08 when the minibob_record ACCESS
 * method was deprecated in migration 052.
 * MiniBob instances now use standard API key authentication.
 */
app.post('/v1/auth/minibob/signin', async (c) => {
  console.log('[auth] Deprecated endpoint called', {
    endpoint: '/v1/auth/minibob/signin',
    ip: c.req.header('x-forwarded-for') || 'unknown'
  })

  return c.json({
    success: false,
    error: {
      code: 'ENDPOINT_DEPRECATED',
      message: 'MiniBob instance authentication has been deprecated',
      details: {
        deprecated_since: '2026-04-08',
        removal_date: '2026-04-08',
        reason: 'Migration 052 deprecated minibob_record ACCESS method',
        old_method: 'POST /v1/auth/minibob/signin with instance_id + api_key',
        new_method: 'Use standard API key authentication with Authorization: ApiKey <key> header',
        migration_guide: 'All endpoints now accept API key authentication directly. No signin required.',
        example: 'curl -H "Authorization: ApiKey <your-key>" https://activity.metabob.com/v2/activities/templates'
      },
      documentation: 'See CLAUDE.md section on API Key Authentication'
    }
  }, 410)
})

/**
 * POST /v2/auth/minibob/signin - DEPRECATED
 *
 * This endpoint was removed on 2026-04-08 when the minibob_record ACCESS
 * method was deprecated in migration 052.
 * MiniBob instances now use standard API key authentication.
 */
app.post('/v2/auth/minibob/signin', async (c) => {
  console.log('[auth] Deprecated endpoint called', {
    endpoint: '/v2/auth/minibob/signin',
    ip: c.req.header('x-forwarded-for') || 'unknown'
  })

  return c.json({
    success: false,
    error: {
      code: 'ENDPOINT_DEPRECATED',
      message: 'MiniBob instance authentication has been deprecated',
      details: {
        deprecated_since: '2026-04-08',
        removal_date: '2026-04-08',
        reason: 'Migration 052 deprecated minibob_record ACCESS method',
        old_method: 'POST /v2/auth/minibob/signin with instance_id + api_key',
        new_method: 'Use standard API key authentication with Authorization: ApiKey <key> header',
        migration_guide: 'All endpoints now accept API key authentication directly. No signin required.',
        example: 'curl -H "Authorization: ApiKey <your-key>" https://activity.metabob.com/v2/activities/templates'
      },
      documentation: 'See CLAUDE.md section on API Key Authentication'
    }
  }, 410)
})

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
// API Key Issuance Endpoint (admin-only; persists to identity-vessel-owned
// api_key table)
// ============================================================================

/**
 * POST /v1/keys/issue
 *
 * Mints a new API key AND persists the metadata row to the api_key table
 * (identity-vessel ownership, see sql/migrations/001-api-keys.surql).
 *
 * Differs from /v1/keys/generate in three ways:
 *   1. Admin-only — caller must present an ApiKey with `admin` scope or a
 *      Bearer JWT with `role: admin`.
 *   2. Persists the row directly; the caller does not need a separate
 *      user-vessel POST to record metadata.
 *   3. Uses the HMAC-embedded keyId as the SurrealDB record id, so
 *      `lookupKeyScopes()` resolves the row by the same identifier
 *      embedded in subsequent ApiKey auth headers.
 *
 * Request body:
 *   {
 *     "user_id": "users:<id>",            // required, record reference
 *     "org_id":  "organizations:<id>",    // required, record reference
 *     "scopes":  ["read","write","admin"], // optional, default ["read","write"]
 *     "expires_in_days": 30,              // optional
 *     "name": "string"                    // optional
 *   }
 *
 * Success response:
 *   { ok: true, key: "<full-canonical-key>", key_id: "<keyId>", expires_at?: "..." }
 *
 * The full key is returned ONCE; only the SHA-256 hash is stored.
 */
app.post('/v1/keys/issue', async (c) => {
  let body: unknown = {};
  try {
    body = await c.req.json();
  } catch {
    body = {};
  }

  const authHeader = c.req.header('Authorization');
  const result = await issueApiKey(body, authHeader);

  if (!result.ok) {
    return c.json(
      {
        success: false,
        error: { code: result.code, message: result.message },
      },
      result.status as any,
    );
  }

  console.log('[KeyIssuance] Issued key:', { key_id: result.key_id });

  return c.json({
    success: true,
    data: {
      key: result.key,
      key_id: result.key_id,
      expires_at: result.expires_at,
    },
  });
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
app.post('/v1/keys/validate', createRateLimitMiddleware('keys_validate', 100), async (c) => {
  try {
    const body = await c.req.json();
    const { api_key } = validateKeySchema.parse(body);

    // Step 1: Validate format, HMAC signature, AND DB-backed scopes.
    // validateKey() merges format + signature checks with a graceful api_key
    // row lookup so admin-scoped keys flow through to the response.  Returns
    // scopes=undefined when no row/no scopes column — we fall back to legacy
    // default below.
    const validation = await validateKey(api_key);

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
        // ?? rather than || so an explicit empty/admin scope set from DB wins.
        scopes: validation.scopes ?? ['read', 'write'],
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

const server = {
  port: config.port,
  fetch: app.fetch
};

// ============================================================================
// Schema Bootstrap (identity-vessel-owned tables)
// ============================================================================
//
// Off by default — production Helm charts run schema migrations through a
// dedicated init container.  Local dev sets SCHEMA_AUTOAPPLY=true so the
// vessel applies its own migrations on startup.  Each migration file uses
// DEFINE … OVERWRITE so a re-run is safe.

if ((process.env.SCHEMA_AUTOAPPLY || 'false').toLowerCase() === 'true') {
  (async () => {
    const { query } = await import('./db/surrealdb');
    const migrations = ['001-api-keys.surql', '002-users-password-hash.surql'];
    for (const file of migrations) {
      try {
        const sql = await Bun.file(`${import.meta.dir}/../sql/migrations/${file}`).text();
        await query(sql);
        console.log('[Schema] applied', { file });
      } catch (err) {
        // Non-fatal — log and continue.  An init-container or operator-run
        // migration is expected to have placed the schema in production.
        console.warn('[Schema] apply failed (may already be applied)', {
          file,
          err: err instanceof Error ? err.message : String(err),
        });
      }
    }
  })().catch((err) => {
    console.warn('[Schema] bootstrap error', {
      err: err instanceof Error ? err.message : String(err),
    });
  });
}

// ============================================================================
// Discovery Vessel Integration (with bootstrap delay)
// ============================================================================

import { discoveryClient, registerWithDiscoveryAfterDelay } from './services/discovery-client';

if (discoveryClient) {
  // Start delayed registration (avoids circular dependency)
  registerWithDiscoveryAfterDelay(discoveryClient)
    .catch((error) => {
      console.error('[Discovery] Bootstrap registration error', { error: error.message });
    });

  // Start heartbeat (handles re-registration if needed)
  discoveryClient.startHeartbeat();
  console.log('[Discovery] Heartbeat started');
} else {
  console.log('[Discovery] Discovery integration disabled');
}

// Graceful shutdown handler
process.on('SIGTERM', async () => {
  console.log('[Server] SIGTERM received, shutting down gracefully');

  if (discoveryClient) {
    await discoveryClient.shutdown();
  }

  console.log('[Server] Graceful shutdown complete');
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('[Server] SIGINT received, shutting down gracefully');

  if (discoveryClient) {
    await discoveryClient.shutdown();
  }

  console.log('[Server] Graceful shutdown complete');
  process.exit(0);
});

export default server;
