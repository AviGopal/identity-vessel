# Identity Vessel

Pure authentication validation service. Validates JWT tokens and API keys, but does not manage user accounts or issue keys.

## Architecture

The identity vessel is a **stateless authentication validator**:
- **Single responsibility**: Validate authentication tokens (JWT or API key)
- **No database dependencies**: Calls user-vessel API when needed for revocation checks
- **Fast**: <2ms average response time
- **Focused**: Does not handle login, signup, password changes, or key generation

**For user management** (login/signup/password change), use `user-vessel`.
**For API key generation/revocation**, use `user-vessel`.

## API Key Format

Keys are base64url-encoded for style and URL safety:

```
Base64(mb_live-<org_id>-<user_id>-<key_id>-<signature>)
```

**Raw format components:**
- `mb_live` or `mb_test`: Environment prefix
- `org_id`: Organization identifier (e.g., `metabob_com`)
- `user_id`: User identifier (e.g., `usr_123`)
- `key_id`: Unique key identifier (e.g., `key_9KC_OLqqSg5H04U`)
- `signature`: HMAC-SHA256 signature (32 chars)

**Example (encoded):**
```
bWJfdGVzdC1tZXRhYm9iX2NvbS11c3JfYWJjMTIzLWtleV85S0NfT0xxcVNnNUgwNFVfX2EwZmQwOWJlMTc2OTkzOGNmNjQwMDg3YzAwMTg1M2Q1
```

**Example (decoded):**
```
mb_test-metabob_com-usr_abc123-key_9KC_OLqqSg5H04U-a0fd09be1769938cf640087c001853d5
```

## Performance

- **Format validation**: ~1μs (constant-time HMAC comparison)
- **Revocation check**: ~1ms (Redis GET)
- **Total validation**: <2ms average

## API Endpoints

### Public Endpoints

**Health Check**
```bash
GET /health
```

**Vessel Capabilities**
```bash
GET /capabilities
```

**Resolve Authentication Impulse**

This is the core endpoint - validates JWT tokens or API keys and returns authentication context.

```bash
POST /v1/auth/resolve
Content-Type: application/json

{
  "impulse": {
    "type": "authentication",
    "pointer": {
      "type": "apiKey",
      "apiKey": "mb_live-..."
    }
  }
}
```

Returns:
```json
{
  "success": true,
  "data": {
    "authenticated": true,
    "orgId": "metabob_com",
    "userId": "usr_123",
    "keyId": "key_abc123",
    "type": "api_key",
    "scopes": ["read", "write"]
  }
}
```

For JWT tokens:
```bash
POST /v1/auth/resolve
Content-Type: application/json

{
  "impulse": {
    "type": "authentication",
    "pointer": {
      "type": "session",
      "token": "eyJhbGc..."
    }
  }
}
```

**MiniBob Instance Authentication**

Special endpoint for autonomous MiniBob instances to authenticate using their instance ID and API key.

```bash
POST /v1/auth/minibob/signin
Content-Type: application/json

{
  "instance_id": "minibob-local-001",
  "api_key": "test-api-key-123"
}
```

Returns:
```json
{
  "success": true,
  "token": "eyJhbGc...",
  "org_id": "metabob_internal"
}
```

### Removed Endpoints

The following endpoints have been moved to `user-vessel`:

- `POST /v2/auth/login` - Login with email/password
- `POST /v2/auth/signup` - Create user and organization
- `PUT /v2/auth/password` - Change password
- `GET /v2/auth/me` - Get current user info
- `POST /v2/api-keys` - Generate new API key
- `DELETE /v2/api-keys/:id` - Revoke API key
- `GET /v2/api-keys` - List API keys

See [user-vessel](../user-vessel/README.md) for user and API key management.

## Integration Patterns

### As HTTP Middleware

Other vessels can call the `/v1/auth/resolve` endpoint to validate authentication tokens:

```typescript
import { Hono } from 'hono';

const app = new Hono();

// Protect all routes under /api
app.use('/api/*', async (c, next) => {
  const authHeader = c.req.header('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return c.json({ error: 'Missing Authorization header' }, 401);
  }

  const token = authHeader.slice(7);

  // Call identity-vessel to validate
  const response = await fetch('http://identity-vessel:8080/v1/auth/resolve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      impulse: {
        type: 'authentication',
        pointer: {
          type: 'apiKey',  // or 'session' for JWT
          apiKey: token    // or token: token for JWT
        }
      }
    })
  });

  const result = await response.json();

  if (!result.success || !result.data.authenticated) {
    return c.json({ error: 'Authentication failed' }, 401);
  }

  // Populate auth context for downstream handlers
  c.set('auth', {
    orgId: result.data.orgId,
    userId: result.data.userId,
    keyId: result.data.keyId,
    type: result.data.type,
    scopes: result.data.scopes
  });

  await next();
});
```

### When to Call User-Vessel Instead

Use user-vessel endpoints for:
- User login/signup: `POST /v2/auth/login`, `POST /v2/auth/signup`
- Password management: `PUT /v2/auth/password`
- API key lifecycle: `POST /v2/api-keys`, `DELETE /v2/api-keys/:id`, `GET /v2/api-keys`
- User profile: `GET /v2/auth/me`

Use identity-vessel only for:
- Validating existing tokens: `POST /v1/auth/resolve`
- MiniBob authentication: `POST /v1/auth/minibob/signin`

## Environment Variables

```bash
# Server configuration
PORT=8080                                    # Server port (default: 8080)

# HMAC validation
API_KEY_SECRET=your-secret-key-min-32-chars  # HMAC signing secret (required)

# Redis (for revocation checks)
REDIS_URL=redis://localhost:6379             # Redis connection (optional)

# SurrealDB (for MiniBob authentication)
SURREALDB_URL=http://surrealdb:8000          # SurrealDB endpoint
SURREALDB_NAMESPACE=activity-system          # Database namespace
SURREALDB_DATABASE=learning_loop             # Database name

# JWT validation
JWT_SECRET=your-jwt-secret                   # JWT signing secret (required)

# User-vessel integration
USER_VESSEL_URL=http://user-vessel:8080      # User-vessel API for revocation checks (optional)
```

## Security

- **Constant-time comparison**: Prevents timing attacks on signature verification
- **HMAC-SHA256**: Cryptographically secure signatures
- **Stateless validation**: No database dependencies for core validation
- **JWT verification**: Standard JWT signature validation with configurable secret
- **Fail-open on Redis**: If Redis is down, revocation checks are skipped (prefer availability)
- **Separation of concerns**: Authentication validation is isolated from account management

## What Changed (v0.2.0)

**Removed from identity-vessel:**
- All user account management (moved to user-vessel)
- API key generation and revocation (moved to user-vessel)
- Cost tracking endpoints (should be moved to user-vessel or activity-api)
- Database dependencies for user data

**Kept in identity-vessel:**
- `/v1/auth/resolve` - Core authentication validation
- `/v1/auth/minibob/signin` - MiniBob instance authentication
- HMAC-based API key validation
- JWT token validation
- Redis-based revocation checks (optional)

**Why:**
- **Single responsibility**: identity-vessel now only validates auth, doesn't manage accounts
- **Stateless**: No user database, faster validation
- **Focused**: Clear separation between "is this token valid?" vs "create a new token"
- **Scalable**: Pure validation can be replicated without state synchronization

## Development

```bash
# Install dependencies
bun install

# Run tests
bun test

# Start development server
bun run dev

# Start production server
bun run start

# Type checking
bun run typecheck
```

## Deployment

See Dockerfile for containerized deployment. Minimal dependencies:
- **Required**: API_KEY_SECRET and JWT_SECRET environment variables
- **Optional**: Redis for revocation checks (fails open if unavailable)
- **Optional**: SurrealDB for MiniBob authentication

## Migration Guide

If you were using the old identity-vessel endpoints:

**Login/Signup:**
```bash
# OLD (removed)
POST http://identity-vessel:8080/v1/auth/login
POST http://identity-vessel:8080/v1/auth/signup

# NEW (use user-vessel)
POST http://user-vessel:8080/v2/auth/login
POST http://user-vessel:8080/v2/auth/signup
```

**API Key Generation:**
```bash
# OLD (removed)
POST http://identity-vessel:8080/v1/keys/generate

# NEW (use user-vessel)
POST http://user-vessel:8080/v2/api-keys
```

**Authentication Validation (unchanged):**
```bash
# Still works the same
POST http://identity-vessel:8080/v1/auth/resolve
```

## Future Enhancements

- [ ] Call user-vessel API for revocation checks instead of Redis
- [ ] Add expiration checking for API keys
- [ ] Add rate limiting per IP/key
- [ ] Support multiple JWT secrets with key rotation
- [ ] Add OpenTelemetry tracing
