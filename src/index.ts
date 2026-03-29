/**
 * Identity Vessel - Lightweight authentication service
 * Provides HMAC-based API key generation and validation
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { apiKeyAuthMiddleware, requireScopes } from './middleware/apiKeyAuth';
import { generateApiKey, generateKeyMetadata } from './services/keyGeneration';
import { resolveAuthentication } from './resolvers/auth';
import { revokeKey, unrevokeKey } from './db/redis';
import { z } from 'zod';
import type { AuthContext } from './types';

const PORT = parseInt(process.env.PORT || '8080');
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
      version: '0.1.0',
      type: 'authentication'
    },
    resolvers: [
      {
        type: 'authentication',
        description: 'Validates API keys with HMAC signatures',
        avgLatency: 2,
        cost: 0.0001
      }
    ],
    endpoints: [
      'POST /v1/auth/resolve - Resolve authentication impulse',
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
    pointer: z.object({
      type: z.literal('apiKey'),
      apiKey: z.string()
    })
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
