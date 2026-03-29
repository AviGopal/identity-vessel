# Identity Vessel

Lightweight authentication service providing HMAC-based API key generation and validation as a vessel resolver.

## Architecture

The identity vessel follows the vessel pattern:
- **Resolvers**: Authentication impulse resolution
- **Activities**: API key lifecycle management
- **No database**: Uses Redis for revocation cache only

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
```
GET /health
```

**Vessel Capabilities**
```
GET /capabilities
```

**Resolve Authentication Impulse**
```
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
    "scopes": ["read", "write"]
  }
}
```

### Protected Endpoints

All endpoints under `/v1/keys/*` require authentication via `Authorization: Bearer <api_key>` header.

**Generate API Key**
```
POST /v1/keys/generate
Authorization: Bearer <api_key>
Content-Type: application/json

{
  "targetUserId": "usr_456",  // Optional, defaults to authenticated user
  "name": "Production API Key",  // Optional
  "expiresInDays": 365,  // Optional
  "scopes": ["read", "write", "admin"]  // Optional, defaults to ["read", "write"]
}
```

Returns (key is only visible once!):
```json
{
  "success": true,
  "data": {
    "key": "mb_live-metabob_com-usr_456-key_xyz-abc123...",
    "keyId": "key_xyz",
    "metadata": {
      "name": "Production API Key",
      "scopes": ["read", "write", "admin"],
      "expiresAt": "2027-03-28T..."
    }
  }
}
```

**Revoke API Key**
```
POST /v1/keys/revoke/:keyId
Authorization: Bearer <api_key>
```

**Un-revoke API Key**
```
POST /v1/keys/unrevoke/:keyId
Authorization: Bearer <api_key>
```

**List API Keys**
```
GET /v1/keys
Authorization: Bearer <api_key>
```

## Using in Other Services

### As Middleware

```typescript
import { Hono } from 'hono';

const app = new Hono();

// Protect all routes under /api
app.use('/api/*', async (c, next) => {
  const authHeader = c.req.header('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return c.json({ error: 'Missing Authorization header' }, 401);
  }

  const apiKey = authHeader.slice(7);

  // Call identity vessel
  const response = await fetch('http://identity-vessel:8080/v1/auth/resolve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      impulse: {
        type: 'authentication',
        pointer: { type: 'apiKey', apiKey }
      }
    })
  });

  const result = await response.json();

  if (!result.success || !result.data.authenticated) {
    return c.json({ error: 'Invalid API key' }, 401);
  }

  // Populate auth context
  c.set('auth', {
    orgId: result.data.orgId,
    userId: result.data.userId,
    keyId: result.data.keyId,
    scopes: result.data.scopes
  });

  await next();
});
```

### As Direct Import (same codebase)

```typescript
import { validateKeyFormat } from '@/services/validation';
import { isKeyRevoked } from '@/db/redis';

export async function authenticateRequest(apiKey: string) {
  // Fast path: format validation
  const validation = validateKeyFormat(apiKey);
  if (!validation.valid) {
    return { authenticated: false, reason: validation.error };
  }

  // Check revocation
  const revoked = await isKeyRevoked(validation.keyId!);
  if (revoked) {
    return { authenticated: false, reason: 'API key revoked' };
  }

  return {
    authenticated: true,
    orgId: validation.orgId,
    userId: validation.userId,
    keyId: validation.keyId
  };
}
```

## Environment Variables

```bash
# Required
API_KEY_SECRET=your-secret-key-min-32-chars  # HMAC signing secret

# Optional
PORT=8080                                    # Server port
REDIS_URL=redis://localhost:6379             # Redis connection
NODE_ENV=production                          # Determines mb_live vs mb_test prefix
```

## Security

- **Constant-time comparison**: Prevents timing attacks on signature verification
- **HMAC-SHA256**: Cryptographically secure signatures
- **No key storage**: Keys are never stored, only metadata
- **Fail-open on Redis**: If Redis is down, revocation checks are skipped (prefer availability)
- **Rate limiting**: TODO - add rate limiting middleware

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

See Dockerfile for containerized deployment. Requires:
- Redis instance for revocation cache
- Secret key for HMAC signing (stored in Kubernetes secret)

## Future Enhancements

- [ ] Store key metadata in SurrealDB
- [ ] Implement expiration checking (currently generates expiresAt but doesn't validate)
- [ ] Add rate limiting per key
- [ ] Add usage analytics
- [ ] Support key rotation (generate new key, revoke old)
- [ ] Add webhook notifications for key events
- [ ] Implement scope-based RBAC enforcement
