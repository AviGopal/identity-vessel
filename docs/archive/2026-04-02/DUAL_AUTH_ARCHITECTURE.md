# Dual Authentication Architecture

The system supports **two independent authentication methods** for different use cases:

## 1. Session-Based Auth (Dashboard Users)

**Use Case:** Human users accessing the web UI via browser

### Flow

```
User visits app.metabob.local
  ↓
Enters credentials (email/password)
  ↓
Cloud Dashboard → metabob-activity-api (or analysis-api)
  ↓
POST /v2/auth/login
{
  "email": "avi@metabob.com",
  "password": "********"
}
  ↓
Server validates:
  - User exists in database
  - Password hash matches (Argon2)
  ↓
Server generates JWT token:
{
  "userId": "usr_abc123",
  "orgId": "metabob_com",
  "email": "avi@metabob.com",
  "exp": 1743434400  // 15 minutes from now
}
  ↓
Server returns token + sets cookie
  ↓
Dashboard stores token in localStorage/cookie
  ↓
Subsequent requests include token:
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

### Implementation (NOT in identity-vessel)

This is handled by metabob-activity-api or metabob-analysis-api:

```typescript
// In metabob-activity-api/src/routes/auth.ts
app.post('/v2/auth/login', async (c) => {
  const { email, password } = await c.req.json();

  // 1. Get user from SurrealDB
  const users = await db.query(`
    SELECT * FROM users
    WHERE email = $email
    LIMIT 1
  `, { email });

  if (!users || users.length === 0) {
    return c.json({ error: 'Invalid credentials' }, 401);
  }

  const user = users[0];

  // 2. Verify password (Argon2)
  const valid = await db.query(`
    RETURN crypto::argon2::compare($hash, $password)
  `, {
    hash: user.password_hash,
    password
  });

  if (!valid) {
    return c.json({ error: 'Invalid credentials' }, 401);
  }

  // 3. Generate JWT token
  const token = await sign({
    userId: user.id,
    orgId: user.org_id,
    email: user.email,
    type: 'session',
    exp: Math.floor(Date.now() / 1000) + (15 * 60) // 15 min
  }, JWT_SECRET);

  // 4. Return token
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
});
```

### Frontend (Cloud Dashboard)

```typescript
// repos/metabob-cloud-dashboard/src/useAuth.tsx
async function login(email: string, password: string) {
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });

  const data = await response.json();

  if (data.success) {
    // Store token
    localStorage.setItem('authToken', data.token);

    // Update auth state
    setUser(data.user);
    setIsAuthenticated(true);
  }
}
```

### Subsequent Requests

```typescript
// All API calls include the JWT token
fetch('/api/projects', {
  headers: {
    'Authorization': `Bearer ${localStorage.getItem('authToken')}`
  }
});
```

---

## 2. API Key Auth (Programmatic Access)

**Use Case:** IDEs, CLI tools, automation scripts, MCP servers

### Flow

```
IDE/CLI tool has API key stored
  ↓
Makes request to any API:
GET /v2/activities/templates
Authorization: Bearer bWJfdGVzdC1tZXRhYm9iX2NvbS11c3JfYXZpLWtleV94...
  ↓
API server (activity-api, concept-db, etc.)
  ↓
Calls identity-vessel for validation:
POST http://identity-vessel:8080/v1/auth/resolve
{
  "impulse": {
    "type": "authentication",
    "pointer": {
      "type": "apiKey",
      "apiKey": "bWJfdGVzdC1tZXRhYm9iX2NvbS11c3JfYXZpLWtleV94..."
    }
  }
}
  ↓
Identity vessel validates:
  - Decode base64
  - Verify HMAC signature
  - Check revocation (Redis)
  ↓
Returns auth context:
{
  "authenticated": true,
  "orgId": "metabob_com",
  "userId": "usr_avi",
  "keyId": "key_abc123",
  "scopes": ["read", "write"]
}
  ↓
API server populates auth context
  ↓
Processes request with org/user isolation
```

### Implementation (identity-vessel)

This is what we just built!

```typescript
// Other services call identity-vessel
async function authenticateApiKey(apiKey: string) {
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
    throw new Error(result.data.reason);
  }

  return result.data; // { orgId, userId, keyId, scopes }
}
```

---

## How They Work Together

### Dashboard Workflow

```
1. User logs in with email/password
   ↓
2. Receives JWT session token
   ↓
3. Uses dashboard to generate API keys
   ↓
4. Dashboard calls (with session token):
   POST /api/auth/proxy/identity-vessel/v1/keys/generate
   Authorization: Bearer <session-jwt>
   ↓
5. Backend validates session, then calls identity-vessel
   ↓
6. Identity vessel generates API key
   ↓
7. User copies API key (shown once!)
   ↓
8. User configures IDE/CLI with API key
   ↓
9. IDE makes API calls with API key
```

### Authentication Decision Tree

```
Is this a browser request?
├─ YES → Use JWT session token
│         (username/password login)
└─ NO → Use API key
          (programmatic access)

Is the Authorization header a JWT?
├─ YES → Validate JWT signature
│         Check expiration
│         Extract userId/orgId from claims
└─ NO → Assume API key
          Call identity-vessel for validation
```

---

## Comparison

| Aspect | Session Auth (JWT) | API Key Auth |
|--------|-------------------|--------------|
| **Use Case** | Dashboard users | IDEs, CLI, automation |
| **Credentials** | Email + Password | API Key |
| **Token Format** | JWT (eyJhbG...) | Base64 HMAC (bWJfdGVz...) |
| **Lifespan** | 15 minutes | 1 year (or until revoked) |
| **Validation** | JWT signature check | HMAC + Redis revocation |
| **Handler** | metabob-activity-api | identity-vessel |
| **Storage** | Not stored (stateless) | Metadata in SurrealDB |
| **Refresh** | Auto-refresh via cookie | Manual rotation |
| **Revocation** | Expiration only | Immediate (Redis) |

---

## Unified Middleware Pattern

Services should support **both** authentication methods:

```typescript
// In metabob-activity-api or any service
app.use('/v2/*', async (c, next) => {
  const authHeader = c.req.header('Authorization');

  if (!authHeader?.startsWith('Bearer ')) {
    return c.json({ error: 'Missing Authorization header' }, 401);
  }

  const token = authHeader.slice(7);

  let authContext;

  // Try JWT first
  if (token.startsWith('eyJ')) {
    // Looks like a JWT
    try {
      const payload = await verify(token, JWT_SECRET, 'HS256');

      authContext = {
        orgId: payload.orgId,
        userId: payload.userId,
        type: 'session',
        email: payload.email
      };
    } catch (error) {
      return c.json({ error: 'Invalid or expired JWT token' }, 401);
    }
  } else {
    // Assume API key - delegate to identity-vessel
    const response = await fetch('http://identity-vessel:8080/v1/auth/resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        impulse: {
          type: 'authentication',
          pointer: { type: 'apiKey', apiKey: token }
        }
      })
    });

    const result = await response.json();

    if (!result.data.authenticated) {
      return c.json({ error: result.data.reason }, 401);
    }

    authContext = {
      orgId: result.data.orgId,
      userId: result.data.userId,
      keyId: result.data.keyId,
      type: 'api_key',
      scopes: result.data.scopes
    };
  }

  // Populate auth context for downstream handlers
  c.set('auth', authContext);

  await next();
});
```

---

## Key Generation Flow (Connecting Both Systems)

**How a dashboard user gets an API key:**

```
1. User logs in with email/password
   → Receives JWT session token
   → Dashboard sets cookie

2. User navigates to Settings → API Keys
   → Dashboard shows API key management UI

3. User clicks "Generate New API Key"
   → Form: Name, Scopes, Expiration

4. Dashboard makes request:
   POST /api/auth/proxy/identity-vessel/v1/keys/generate
   Authorization: Bearer <session-jwt>
   {
     "name": "My IDE Key",
     "scopes": ["read", "write"],
     "expiresInDays": 365
   }

5. Backend (metabob-activity-api) receives request
   → Validates JWT session token
   → Extracts orgId/userId from JWT
   → Makes authenticated request to identity-vessel:
     POST http://identity-vessel:8080/v1/keys/generate
     Authorization: Bearer <admin-api-key>
     {
       "targetUserId": "<userId-from-jwt>",
       "name": "My IDE Key",
       "scopes": ["read", "write"],
       "expiresInDays": 365
     }

6. Identity vessel generates API key
   → Creates HMAC signature
   → Stores metadata in SurrealDB
   → Returns key (ONLY TIME IT'S VISIBLE!)

7. Backend returns key to dashboard

8. Dashboard shows key in modal
   → User copies key
   → Modal closes
   → Key is NEVER shown again

9. User pastes key into IDE config
   → IDE now uses API key for all requests
   → No more username/password needed
```

---

## Security Boundaries

### Session Tokens (JWT)

**Stored:**
- Not stored server-side (stateless)
- Client stores in localStorage or cookie

**Validation:**
- JWT signature verified with secret
- Expiration checked
- No database lookup needed

**Revocation:**
- Cannot be revoked (expires automatically after 15 min)
- For immediate revocation, need token blacklist (Redis)

### API Keys

**Stored:**
- NEVER stored (not even hashed)
- Only metadata stored (keyId, name, scopes, expiration)

**Validation:**
- HMAC signature verified with secret
- Redis checked for revocation
- Constant-time comparison

**Revocation:**
- Immediate (Redis cache updated)
- All future requests rejected within ~1ms

---

## Common Patterns

### 1. Dashboard Making API Calls (Session Auth)

```typescript
// Dashboard authenticated user fetching data
const response = await fetch('/api/v2/activities/templates', {
  headers: {
    'Authorization': `Bearer ${sessionToken}` // JWT
  }
});
```

### 2. IDE Making API Calls (API Key Auth)

```typescript
// IDE tool making API calls
const response = await fetch('https://api.metabob.com/v2/activities/templates', {
  headers: {
    'Authorization': `Bearer ${apiKey}` // Base64 HMAC key
  }
});
```

### 3. Backend Validating Either

```typescript
// Server accepts both
if (token.startsWith('eyJ')) {
  // JWT session
  validateJWT(token);
} else {
  // API key
  await validateApiKey(token);
}
```

---

## Summary

**Two systems, two purposes:**

1. **Session Auth (Username/Password → JWT)**
   - For: Dashboard users (humans in browsers)
   - Handler: metabob-activity-api (or analysis-api)
   - Lifespan: 15 minutes
   - Format: JWT (eyJhbG...)
   - Revocation: Expiration only

2. **API Key Auth (HMAC Keys)**
   - For: IDEs, CLI, automation (programmatic access)
   - Handler: identity-vessel (what we just built!)
   - Lifespan: 1 year (configurable)
   - Format: Base64 HMAC (bWJfdGVz...)
   - Revocation: Immediate (Redis)

**They connect when:**
- Dashboard user (session auth) generates API keys for their IDE
- Backend validates session token, then calls identity-vessel to generate API key
- User gets API key, uses it for programmatic access

**Identity vessel does NOT handle username/password authentication.**
It only handles API key validation for programmatic access.
