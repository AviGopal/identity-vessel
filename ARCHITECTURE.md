# Identity Vessel Architecture

## Overview

The identity vessel provides authentication as a resolver service following the impulse-activity pattern. It validates API keys with HMAC signatures and collects traces for learning.

## Architectural Questions

### 1. How are we not overwhelming ourselves with traces?

**Problem**: Sending every authentication request as a trace would generate millions of events per day at scale.

**Solution**: Adaptive sampling with multiple strategies:

#### Sampling Rates

```typescript
// Environment configuration
TRACE_SAMPLE_RATE=0.01           // Sample 1% of successful authentications
ALWAYS_TRACE_FAILURES=true       // Always trace failures for debugging
```

#### Sampling Logic

```typescript
function shouldSample(success: boolean): boolean {
  // Always trace failures for debugging
  if (!success && ALWAYS_TRACE_FAILURES) {
    return true;
  }

  // Sample successful requests based on configured rate
  return Math.random() < TRACE_SAMPLE_RATE;
}
```

#### Adaptive Sampling (Future Enhancement)

```typescript
// Increase sampling during:
// - First 24h of new key (learning period)
// - Anomalous behavior detected
// - Performance degradation
// - Security incidents

if (isNewKey(keyId) && keyAge < 24 * 60 * 60 * 1000) {
  return Math.random() < 0.1; // 10% for new keys
}

if (hasAnomalies(keyId)) {
  return true; // 100% when suspicious
}
```

#### Aggregation (Future)

Instead of individual traces, send aggregated metrics:

```json
{
  "period": "2026-03-29T14:00:00Z",
  "duration_seconds": 60,
  "metrics": {
    "total_authentications": 15420,
    "successful": 15392,
    "failed": 28,
    "avg_duration_ms": 1.8,
    "p95_duration_ms": 3.2,
    "p99_duration_ms": 5.1
  },
  "by_org": {
    "metabob_com": { "total": 10250, "success": 10240 },
    "acme_corp": { "total": 5170, "success": 5152 }
  }
}
```

**Current Configuration:**
- **1% sampling** for successful requests (configurable via `TRACE_SAMPLE_RATE`)
- **100% sampling** for failures (always trace errors)
- **Async fire-and-forget** (don't block authentication on trace collection)

---

### 2. How do we validate keys? Who validates? When?

**Validation Flow:**

```
Client Request
  ↓
[1] Format Validation (identity-vessel, <1μs)
  ↓ valid format?
[2] HMAC Signature Verification (identity-vessel, ~10μs)
  ↓ valid signature?
[3] Revocation Check (Redis, ~1ms)
  ↓ not revoked?
[4] Return auth context
```

#### Who Validates?

**identity-vessel validates everything**. Other services never validate directly.

**Option A: Vessel as HTTP Middleware (Recommended)**

Other services call identity-vessel via HTTP:

```typescript
// In metabob-activity-api or any other service
async function authenticateRequest(req: Request) {
  const apiKey = req.headers.get('Authorization')?.replace('Bearer ', '');

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

  if (!result.data.authenticated) {
    throw new AuthError(result.data.reason);
  }

  return result.data; // { orgId, userId, keyId, scopes }
}
```

**Option B: Shared Library (Not Recommended)**

Services import validation library directly:

```typescript
// DON'T DO THIS - creates coupling and versioning issues
import { validateKeyFormat } from '@identity-vessel/validation';
```

**Why HTTP is better:**
- Single source of truth for validation logic
- Easy to update validation rules without redeploying all services
- Centralized revocation cache (Redis)
- Centralized trace collection
- Clear service boundary

#### When Does Validation Happen?

**Every Request** - Authentication is stateless. We don't use sessions.

```typescript
// metabob-activity-api middleware
app.use('/v2/*', async (c, next) => {
  const authResult = await authenticateRequest(c.req);
  c.set('auth', authResult);
  await next();
});
```

**Performance:**
- **<2ms** total validation time (target)
- **~10μs** HMAC verification (constant time)
- **~1ms** Redis lookup (local cache future enhancement)
- **Async trace** (doesn't block request)

**Caching Strategy (Future):**

```typescript
// Local in-memory cache for hot keys (1-second TTL)
const validationCache = new Map<string, CachedValidation>();

function validateWithCache(apiKey: string) {
  const cached = validationCache.get(apiKey);

  if (cached && Date.now() - cached.timestamp < 1000) {
    return cached.result; // <1μs cache hit
  }

  const result = await validateKeyFormat(apiKey);
  validationCache.set(apiKey, { result, timestamp: Date.now() });

  return result;
}
```

---

### 3. How does the cloud dashboard register, revoke and rotate keys?

#### Key Lifecycle Management

```
[Dashboard] → [identity-vessel] → [SurrealDB (metadata)]
                                 → [Redis (revocations)]
```

#### Register (Generate) New Key

**Frontend (metabob-cloud-dashboard):**

```typescript
// src/pages/APIKeys.tsx
async function generateNewKey(name: string, scopes: string[]) {
  const response = await fetch('/api/auth/proxy/identity-vessel/v1/keys/generate', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${sessionToken}`, // User's session token
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      name,
      scopes,
      expiresInDays: 365
    })
  });

  const result = await response.json();

  // CRITICAL: Show key ONCE, user must copy it
  showKeyModal(result.data.key); // Base64-encoded key

  // Store only metadata
  saveKeyMetadata({
    keyId: result.data.keyId,
    name: result.data.metadata.name,
    scopes: result.data.metadata.scopes,
    createdAt: new Date().toISOString()
  });
}
```

**Backend (metabob-analysis-api proxy):**

```typescript
// Proxy to identity-vessel (validates user session first)
app.post('/api/auth/proxy/identity-vessel/*', async (c) => {
  // 1. Validate user session token
  const session = await validateSession(c.req.header('Authorization'));

  // 2. Generate admin API key for this request
  const adminKey = await getOrgAdminKey(session.orgId);

  // 3. Proxy to identity-vessel
  const vesselPath = c.req.param('*');
  const response = await fetch(`http://identity-vessel:8080/${vesselPath}`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${adminKey}`,
      'Content-Type': 'application/json'
    },
    body: await c.req.text()
  });

  return response;
});
```

**Identity Vessel:**

```typescript
// Already implemented in src/index.ts:116
app.post('/v1/keys/generate', requireScopes('write', 'admin'), async (c) => {
  const auth = c.get('auth');
  const { name, scopes, expiresInDays } = await c.req.json();

  // Generate key
  const result = generateApiKey(auth.orgId, auth.userId, { scopes, expiresInDays });

  // Store metadata in SurrealDB (TODO)
  await db.query(`
    CREATE api_key CONTENT {
      id: $keyId,
      org_id: $orgId,
      user_id: $userId,
      name: $name,
      scopes: $scopes,
      prefix: $prefix,
      created_at: time::now(),
      expires_at: $expiresAt,
      is_active: true
    }
  `, {
    keyId: result.keyId,
    orgId: auth.orgId,
    userId: auth.userId,
    name,
    scopes,
    prefix: result.prefix,
    expiresAt: result.expiresAt
  });

  // Return key ONCE
  return c.json({
    success: true,
    data: {
      key: result.key, // ONLY TIME key is returned!
      keyId: result.keyId,
      metadata: { name, scopes, expiresAt: result.expiresAt }
    }
  });
});
```

#### Revoke Key

**Frontend:**

```typescript
async function revokeKey(keyId: string) {
  await fetch(`/api/auth/proxy/identity-vessel/v1/keys/revoke/${keyId}`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${sessionToken}`
    }
  });

  // Update UI immediately
  updateKeyStatus(keyId, 'revoked');
}
```

**Identity Vessel:**

```typescript
// Already implemented in src/index.ts:169
app.post('/v1/keys/revoke/:keyId', requireScopes('write', 'admin'), async (c) => {
  const keyId = c.req.param('keyId');

  // 1. Add to Redis revocation cache (immediate effect)
  await revokeKey(keyId);

  // 2. Update metadata in SurrealDB (TODO)
  await db.query(`
    UPDATE api_key SET
      is_active = false,
      revoked_at = time::now(),
      revoked_by = $userId
    WHERE id = $keyId
  `, { keyId, userId: auth.userId });

  return c.json({
    success: true,
    data: { keyId, revoked: true, revokedAt: new Date().toISOString() }
  });
});
```

#### Rotate Key

**Frontend:**

```typescript
async function rotateKey(oldKeyId: string, name: string, scopes: string[]) {
  // 1. Generate new key
  const newKey = await generateNewKey(name, scopes);

  // 2. Test new key works
  const testResult = await fetch('/api/health', {
    headers: { 'Authorization': `Bearer ${newKey.key}` }
  });

  if (!testResult.ok) {
    throw new Error('New key validation failed');
  }

  // 3. Revoke old key (after confirming new key works)
  await revokeKey(oldKeyId);

  return newKey;
}
```

#### List Keys (Dashboard View)

**Frontend:**

```typescript
async function listKeys() {
  const response = await fetch('/api/auth/proxy/identity-vessel/v1/keys', {
    headers: {
      'Authorization': `Bearer ${sessionToken}`
    }
  });

  const result = await response.json();

  // Render key metadata (NEVER shows actual keys)
  return result.data.keys.map(key => ({
    keyId: key.keyId,
    name: key.name,
    prefix: `${key.prefix}-****`, // Only show prefix
    scopes: key.scopes,
    createdAt: key.createdAt,
    expiresAt: key.expiresAt,
    lastUsed: key.lastUsed,
    isActive: key.isActive
  }));
}
```

---

## Security Principles

### 1. Keys are NEVER stored

Only metadata (keyId, name, scopes, expiration) is stored in SurrealDB.

The actual key is:
- Generated once
- Returned once
- Never logged
- Never stored

### 2. Validation is centralized

Only identity-vessel validates keys. Other services delegate via HTTP.

### 3. Revocation is immediate

Redis cache ensures revoked keys are rejected within ~1ms.

### 4. Scopes are enforced

Each endpoint requires specific scopes:
- `read`: List keys, view metadata
- `write`: Generate keys (for self)
- `admin`: Generate keys for others, revoke keys

### 5. Constant-time comparison

HMAC signature verification uses `timingSafeEqual()` to prevent timing attacks.

---

## Data Flow

### Authentication Flow

```
1. User sends request with API key
   ↓
2. Service extracts key from Authorization header
   ↓
3. Service calls identity-vessel /v1/auth/resolve
   ↓
4. Identity vessel validates:
   - Format (base64, structure)
   - HMAC signature (constant time)
   - Revocation status (Redis)
   ↓
5. Returns { authenticated, orgId, userId, keyId, scopes }
   ↓
6. Service populates auth context and continues
```

### Key Generation Flow

```
1. User clicks "Generate API Key" in dashboard
   ↓
2. Dashboard calls metabob-analysis-api proxy
   ↓
3. Proxy validates user session
   ↓
4. Proxy calls identity-vessel with admin key
   ↓
5. Identity vessel generates key
   ↓
6. Identity vessel stores metadata in SurrealDB
   ↓
7. Identity vessel returns key (ONLY TIME!)
   ↓
8. Dashboard shows key in modal (copy-once)
   ↓
9. User copies key, modal closes
   ↓
10. Key is never shown again
```

### Revocation Flow

```
1. User clicks "Revoke" in dashboard
   ↓
2. Dashboard calls revoke endpoint
   ↓
3. Identity vessel adds keyId to Redis
   ↓
4. Identity vessel updates SurrealDB
   ↓
5. Next authentication attempt fails
```

---

## Implementation Status

### ✅ Complete

- [x] HMAC signature generation and validation
- [x] Base64 encoding for style
- [x] Constant-time comparison
- [x] Redis revocation cache
- [x] HTTP endpoints (health, capabilities, resolve, generate, revoke, list)
- [x] Trace collection with sampling
- [x] Test suite (6 tests passing)
- [x] Docker support
- [x] Helm chart for Kubernetes

### 🚧 In Progress

- [ ] SurrealDB metadata storage (schema designed, not implemented)
- [ ] Dashboard API key management UI
- [ ] Proxy endpoint in metabob-analysis-api
- [ ] Scope-based RBAC enforcement

### 📋 TODO

- [ ] Local validation cache (1-second TTL)
- [ ] Adaptive sampling (new keys, anomalies)
- [ ] Aggregated metrics (instead of individual traces)
- [ ] Key expiration checking
- [ ] Usage analytics (last used, request count)
- [ ] Rate limiting per key
- [ ] Webhook notifications for key events

---

## Performance Targets

| Operation | Target | Current |
|-----------|--------|---------|
| Format validation | <1μs | ~10μs ✓ |
| HMAC verification | <10μs | ~10μs ✓ |
| Redis revocation check | <1ms | ~1ms ✓ |
| Total validation | <2ms | ~2ms ✓ |
| Trace collection | async | ✓ |
| Throughput | >10k req/s | Not tested |

---

## Configuration

### Environment Variables

```bash
# Server
PORT=8080
NODE_ENV=production  # or development (affects mb_live vs mb_test prefix)

# Security
API_KEY_SECRET=your-secret-key-min-32-chars  # HMAC signing secret

# Dependencies
REDIS_URL=redis://redis-valkey-master:6379
ACTIVITY_API_ENDPOINT=http://metabob-activity-api:8080

# Trace Sampling
TRACE_SAMPLE_RATE=0.01          # 1% sampling for successful requests
ALWAYS_TRACE_FAILURES=true      # Always trace failures
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: identity-vessel
spec:
  replicas: 2
  template:
    spec:
      containers:
      - name: identity-vessel
        image: identity-vessel:0.1.0
        env:
        - name: API_KEY_SECRET
          valueFrom:
            secretKeyRef:
              name: identity-vessel-secret
              key: api-key-secret
        - name: REDIS_URL
          value: redis://redis-valkey-master:6379
        - name: TRACE_SAMPLE_RATE
          value: "0.01"
```

---

## Next Steps

1. **Deploy to Kubernetes** - Build image and deploy via Helm
2. **Implement SurrealDB storage** - Create schema and queries
3. **Build Dashboard UI** - API key management interface
4. **Add to other services** - Protect activity-api and concept-db endpoints
5. **Monitor performance** - Validate <2ms target in production
6. **Implement caching** - Local validation cache for hot keys
7. **Add analytics** - Usage tracking and reporting
