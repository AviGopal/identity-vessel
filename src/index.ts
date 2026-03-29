/**
 * Identity Vessel - Lightweight authentication service
 * Provides HMAC-based API key generation and validation
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { sign, verify } from 'hono/jwt';
import { apiKeyAuthMiddleware, requireScopes } from './middleware/apiKeyAuth';
import { generateApiKey, generateKeyMetadata } from './services/keyGeneration';
import { resolveAuthentication } from './resolvers/auth';
import { revokeKey, unrevokeKey } from './db/redis';
import { getSurrealDB, query } from './db/surrealdb';
import { z } from 'zod';
import type { AuthContext } from './types';

const PORT = parseInt(process.env.PORT || '8080');
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';

type Variables = {
  auth: AuthContext;
};

const app = new Hono<{ Variables: Variables }>();

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
      version: '0.1.0',
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
      'POST /v1/auth/resolve - Resolve authentication impulse (JWT or API key)',
      'POST /v1/auth/login - Login with email/password',
      'POST /v1/auth/signup - Create user and organization',
      'GET /v1/auth/me - Get current user from JWT',
      'POST /v1/keys/generate - Generate new API key (authenticated)',
      'POST /v1/keys/revoke - Revoke API key (authenticated)',
      'GET /v1/keys - List API keys (authenticated)'
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
// Username/Password Authentication Endpoints
// ============================================================================

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1)
});

app.post('/v1/auth/login', async (c) => {
  try {
    const body = await c.req.json();
    const { email, password } = loginSchema.parse(body);

    const db = await getSurrealDB();

    // Query user by email
    const users = await db.query<any[]>(`
      SELECT * FROM users
      WHERE email = $email
      LIMIT 1
    `, { email });

    if (!users || users[0].length === 0) {
      return c.json({
        success: false,
        error: 'Invalid credentials'
      }, 401);
    }

    const user = users[0][0] as any;

    // Verify password using SurrealDB's Argon2 compare
    const valid = await db.query<boolean[]>(`
      RETURN crypto::argon2::compare($hash, $password)
    `, {
      hash: user.password_hash,
      password
    });

    if (!(valid[0] as boolean)) {
      return c.json({
        success: false,
        error: 'Invalid credentials'
      }, 401);
    }

    // Generate JWT session token (15 min expiry)
    const token = await sign({ alg: "HS256",
      userId: user.id,
      orgId: user.org_id,
      email: user.email,
      type: 'session',
      exp: Math.floor(Date.now() / 1000) + (15 * 60)
    }, JWT_SECRET);

    return c.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        orgId: user.org_id
      }
    });
  } catch (error) {
    console.error('[Login] Error:', error);
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Login failed'
    }, 500);
  }
});

const signupSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  name: z.string().min(1),
  orgName: z.string().min(1)
});

app.post('/v1/auth/signup', async (c) => {
  try {
    const body = await c.req.json();
    const { email, password, name, orgName } = signupSchema.parse(body);

    const db = await getSurrealDB();

    // Hash password using SurrealDB's Argon2
    const passwordHash = await db.query<string[]>(`
      RETURN crypto::argon2::generate($password)
    `, { password });

    // Create organization
    const org = await db.query<any[]>(`
      CREATE organizations SET
        name = $orgName,
        created_at = time::now()
      RETURN id
    `, { orgName });

    if (!org || org[0].length === 0) {
      return c.json({
        success: false,
        error: 'Failed to create organization'
      }, 500);
    }

    const orgData = org[0] as any;

    // Create user
    const user = await db.query<any[]>(`
      CREATE users SET
        email = $email,
        password_hash = $passwordHash,
        name = $name,
        org_id = $orgId,
        created_at = time::now()
      RETURN *
    `, {
      email,
      passwordHash: passwordHash[0],
      name,
      orgId: orgData.id
    });

    if (!user || user[0].length === 0) {
      return c.json({
        success: false,
        error: 'Failed to create user'
      }, 500);
    }

    const newUser = user[0][0] as any;

    // Generate JWT session token (15 min expiry)
    const token = await sign({ alg: "HS256",
      userId: newUser.id,
      orgId: orgData.id,
      email,
      type: 'session',
      exp: Math.floor(Date.now() / 1000) + (15 * 60)
    }, JWT_SECRET);

    return c.json({
      success: true,
      token,
      user: {
        id: newUser.id,
        email,
        name,
        orgId: org[0].id
      }
    });
  } catch (error) {
    console.error('[Signup] Error:', error);
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Signup failed'
    }, 500);
  }
});

app.get('/v1/auth/me', async (c) => {
  try {
    const authHeader = c.req.header('Authorization');

    if (!authHeader?.startsWith('Bearer ')) {
      return c.json({
        success: false,
        error: 'Missing Authorization header'
      }, 401);
    }

    const token = authHeader.slice(7);

    const payload = await verify(token, JWT_SECRET, "HS256") as any;

    return c.json({
      success: true,
      user: {
        id: payload.userId,
        email: payload.email,
        orgId: payload.orgId
      }
    });
  } catch (error) {
    return c.json({
      success: false,
      error: 'Invalid or expired token'
    }, 401);
  }
});

// ============================================================================
// Protected Endpoints (require API key authentication)
// ============================================================================

app.use('/v1/keys/*', apiKeyAuthMiddleware);

// Generate new API key
const generateSchema = z.object({
  targetUserId: z.string().optional(),
  name: z.string().optional(),
  expiresInDays: z.number().min(1).max(365).optional(),
  scopes: z.array(z.string()).optional()
});

app.post('/v1/keys/generate', requireScopes('write', 'admin'), async (c) => {
  try {
    const auth = c.get('auth') as AuthContext;
    const body = await c.req.json();
    const options = generateSchema.parse(body);
    
    // Use authenticated user's org, but allow specifying different user
    const targetUserId = options.targetUserId || auth.userId;
    
    // Generate key
    const result = generateApiKey(auth.orgId, targetUserId, options);
    
    // In production, you would store metadata in SurrealDB here
    const metadata = generateKeyMetadata(
      auth.orgId,
      targetUserId,
      result.keyId,
      result.prefix,
      options
    );
    
    console.log('[KeyGen] Generated key:', {
      keyId: result.keyId,
      orgId: auth.orgId,
      userId: targetUserId,
      expiresAt: result.expiresAt
    });
    
    // Return the key (only time it's visible!)
    return c.json({
      success: true,
      data: {
        key: result.key,
        keyId: result.keyId,
        metadata: {
          name: metadata.name,
          scopes: metadata.scopes,
          expiresAt: result.expiresAt
        }
      }
    });
  } catch (error) {
    return c.json({
      success: false,
      error: {
        code: 'GENERATION_FAILED',
        message: error instanceof Error ? error.message : 'Unknown error'
      }
    }, 400);
  }
});

// Revoke API key
app.post('/v1/keys/revoke/:keyId', requireScopes('write', 'admin'), async (c) => {
  try {
    const auth = c.get('auth') as AuthContext;
    const keyId = c.req.param('keyId');
    
    // Revoke in Redis (immediate effect)
    await revokeKey(keyId);
    
    console.log('[KeyRevoke] Revoked key:', {
      keyId,
      revokedBy: auth.userId,
      orgId: auth.orgId
    });
    
    return c.json({
      success: true,
      data: {
        keyId,
        revoked: true,
        revokedAt: new Date().toISOString()
      }
    });
  } catch (error) {
    return c.json({
      success: false,
      error: {
        code: 'REVOCATION_FAILED',
        message: error instanceof Error ? error.message : 'Unknown error'
      }
    }, 500);
  }
});

// Un-revoke API key (restore access)
app.post('/v1/keys/unrevoke/:keyId', requireScopes('write', 'admin'), async (c) => {
  try {
    const auth = c.get('auth') as AuthContext;
    const keyId = c.req.param('keyId');
    
    await unrevokeKey(keyId);
    
    console.log('[KeyUnrevoke] Restored key:', {
      keyId,
      restoredBy: auth.userId,
      orgId: auth.orgId
    });
    
    return c.json({
      success: true,
      data: {
        keyId,
        revoked: false,
        restoredAt: new Date().toISOString()
      }
    });
  } catch (error) {
    return c.json({
      success: false,
      error: {
        code: 'RESTORE_FAILED',
        message: error instanceof Error ? error.message : 'Unknown error'
      }
    }, 500);
  }
});

// List API keys (metadata only, never the actual keys)
app.get('/v1/keys', requireScopes('read'), async (c) => {
  const auth = c.get('auth') as AuthContext;
  
  // In production, query SurrealDB for api_keys WHERE org_id = auth.orgId
  // For now, return placeholder
  return c.json({
    success: true,
    data: {
      keys: [
        {
          keyId: auth.keyId,
          name: 'Current API Key',
          scopes: auth.scopes,
          isActive: true,
          createdAt: new Date().toISOString()
        }
      ]
    }
  });
});

// ============================================================================
// Start Server
// ============================================================================

console.log('[IdentityVessel] Starting server on port ' + PORT);

export default {
  port: PORT,
  fetch: app.fetch
};
