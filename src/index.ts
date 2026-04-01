/**
 * Identity Vessel - Pure authentication validation service
 * Validates JWT tokens and API keys. Does not manage user accounts or issue keys.
 *
 * For account management (login/signup/password change), use user-vessel.
 * For API key generation/revocation, use user-vessel.
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { resolveAuthentication } from './resolvers/auth';
import { authenticateMiniBobInstance, handleAuthError } from './services/minibob-auth';
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
      version: '0.2.0',
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
      'POST /v1/auth/minibob/signin - MiniBob instance authentication'
    ],
    notes: [
      'For user management (login/signup/password): use user-vessel',
      'For API key generation/revocation: use user-vessel'
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
// NOTE: Removed endpoints
// ============================================================================
// The following endpoints have been moved to user-vessel:
// - POST /v2/auth/login - Login with email/password
// - POST /v2/auth/signup - Create user and organization
// - PUT /v2/auth/password - Change password
// - GET /v2/auth/me - Get current user
// - POST /v2/api-keys - Generate new API key
// - DELETE /v2/api-keys/:id - Revoke API key
// - GET /v2/api-keys - List API keys
//
// Cost tracking endpoints should be moved to user-vessel or activity-api:
// - POST /v2/costs/record
// - GET /v2/costs/org/:id
// - GET /v2/costs/org/:id/projects
// - GET /v2/costs/org/:id/goals
// - GET /v2/costs/org/:id/timeline
//
// identity-vessel is now focused purely on authentication validation.
// ============================================================================

// ============================================================================
// Start Server
// ============================================================================

console.log('[IdentityVessel] Starting server on port ' + config.port);

export default {
  port: config.port,
  fetch: app.fetch
};
