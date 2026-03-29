# Corrected Architecture: Identity Vessel as Single Auth Provider

## Core Principle

**Identity vessel is responsible for ALL authentication**, not just API keys.

### Why This Makes Sense

1. **Single Responsibility** - One vessel for all identity/authentication concerns
2. **Consistent Pattern** - All services delegate authentication to identity vessel
3. **Vessel Pattern** - Vessels provide capabilities where data lives
4. **Easier to Secure** - One codebase to audit for security
5. **Easier to Extend** - Add OAuth, SSO, MFA in one place

---

## Identity Vessel Should Provide

### 1. Username/Password Authentication ❌ **TODO**

```
POST /v1/auth/login
{
  "email": "avi@metabob.com",
  "password": "password123"
}

Response:
{
  "success": true,
  "token": "eyJhbGci...",  // JWT session token (15 min)
  "user": {
    "id": "usr_avi",
    "email": "avi@metabob.com",
    "orgId": "metabob_com"
  }
}
```

### 2. API Key Authentication ✅ **COMPLETE**

```
POST /v1/auth/resolve
{
  "impulse": {
    "type": "authentication",
    "pointer": {
      "type": "apiKey",
      "apiKey": "bWJfdGVzdC1tZXRh..."
    }
  }
}

Response:
{
  "authenticated": true,
  "orgId": "metabob_com",
  "userId": "usr_avi",
  "keyId": "key_abc123",
  "scopes": ["read", "write"]
}
```

### 3. User Management ❌ **TODO**

```
POST /v1/auth/signup
PUT /v1/auth/password
GET /v1/auth/me
```

---

## Updated Flow

### Dashboard Login (Username/Password)

```
┌─────────┐
│ Browser │
└────┬────┘
     │
     │ POST /v1/auth/login
     │ email + password
     ▼
┌──────────────────┐
│ identity-vessel  │
│                  │
│ 1. Query users   │
│    from SurrealDB│
│ 2. Verify Argon2 │
│    password hash │
│ 3. Generate JWT  │
│    (15 min)      │
└────┬─────────────┘
     │
     │ Return: { token, user }
     ▼
┌─────────┐
│ Browser │
│ Stores  │
│ JWT     │
└─────────┘
```

### API Request (Either Auth Method)

```
┌─────────┐
│  Client │
└────┬────┘
     │
     │ Authorization: Bearer <token>
     │ (could be JWT or API key)
     ▼
┌──────────────────┐
│ activity-api     │
│ or concept-db    │
│ or any service   │
└────┬─────────────┘
     │
     │ POST /v1/auth/resolve
     │ { "impulse": { "type": "authentication", ... } }
     ▼
┌──────────────────┐
│ identity-vessel  │
│                  │
│ Detect type:     │
│ - Starts "eyJ"?  │
│   → JWT session  │
│ - Else?          │
│   → API key      │
└────┬─────────────┘
     │
     │ Return: { authenticated, orgId, userId, ... }
     ▼
┌──────────────────┐
│ service          │
│ populates auth   │
│ context          │
└──────────────────┘
```

---

## Implementation Plan

### Phase 1: Add Login to Identity Vessel

**File:** `repos/identity-vessel/src/index.ts`

Add these endpoints:

```typescript
import { sign, verify } from 'hono/jwt';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';

// Login endpoint
app.post('/v1/auth/login', async (c) => {
  const { email, password } = await c.req.json();

  // Query SurrealDB for user
  const db = await connectToSurrealDB();
  const users = await db.query(`
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

  const user = users[0][0];

  // Verify password (Argon2)
  const valid = await db.query(`
    RETURN crypto::argon2::compare($hash, $password)
  `, {
    hash: user.password_hash,
    password
  });

  if (!valid[0]) {
    return c.json({
      success: false,
      error: 'Invalid credentials'
    }, 401);
  }

  // Generate JWT
  const token = await sign({
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
});

// Signup endpoint
app.post('/v1/auth/signup', async (c) => {
  const { email, password, name, orgName } = await c.req.json();

  const db = await connectToSurrealDB();

  // Hash password
  const passwordHash = await db.query(`
    RETURN crypto::argon2::generate($password)
  `, { password });

  // Create organization
  const org = await db.query(`
    CREATE organizations SET
      name = $orgName,
      created_at = time::now()
    RETURN id
  `, { orgName });

  // Create user
  const user = await db.query(`
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
    orgId: org[0].id
  });

  // Generate JWT
  const token = await sign({
    userId: user[0].id,
    orgId: org[0].id,
    email,
    type: 'session',
    exp: Math.floor(Date.now() / 1000) + (15 * 60)
  }, JWT_SECRET);

  return c.json({
    success: true,
    token,
    user: {
      id: user[0].id,
      email,
      name,
      orgId: org[0].id
    }
  });
});

// Get current user
app.get('/v1/auth/me', async (c) => {
  const authHeader = c.req.header('Authorization');

  if (!authHeader?.startsWith('Bearer ')) {
    return c.json({ error: 'Missing Authorization header' }, 401);
  }

  const token = authHeader.slice(7);

  try {
    const payload = await verify(token, JWT_SECRET);

    return c.json({
      success: true,
      user: {
        id: payload.userId,
        email: payload.email,
        orgId: payload.orgId
      }
    });
  } catch (error) {
    return c.json({ error: 'Invalid or expired token' }, 401);
  }
});
```

### Phase 2: Update `/v1/auth/resolve` to Handle Both

**File:** `repos/identity-vessel/src/resolvers/auth.ts`

```typescript
export async function resolveAuthentication(
  impulse: AuthenticationImpulse
): Promise<AuthenticationResult> {
  const token = impulse.pointer.apiKey || impulse.pointer.token;

  // Detect authentication type
  if (token.startsWith('eyJ')) {
    // JWT session token
    return await resolveJWT(token);
  } else {
    // API key (HMAC)
    return await resolveAPIKey(token);
  }
}

async function resolveJWT(token: string): Promise<AuthenticationResult> {
  try {
    const payload = await verify(token, JWT_SECRET);

    return {
      authenticated: true,
      orgId: payload.orgId,
      userId: payload.userId,
      type: 'session',
      scopes: ['read', 'write'] // Sessions get full access
    };
  } catch (error) {
    return {
      authenticated: false,
      reason: 'Invalid or expired JWT token'
    };
  }
}

async function resolveAPIKey(apiKey: string): Promise<AuthenticationResult> {
  // Existing API key logic
  const validation = validateKeyFormat(apiKey);

  if (!validation.valid) {
    return {
      authenticated: false,
      reason: validation.error || 'Invalid API key'
    };
  }

  const revoked = await isKeyRevoked(validation.keyId!);

  if (revoked) {
    return {
      authenticated: false,
      reason: 'API key has been revoked'
    };
  }

  return {
    authenticated: true,
    orgId: validation.orgId,
    userId: validation.userId,
    keyId: validation.keyId,
    type: 'api_key',
    scopes: validation.scopes || ['read', 'write']
  };
}
```

### Phase 3: Update Dashboard to Call Identity Vessel

**File:** `repos/metabob-cloud-dashboard/src/useAuth.tsx`

```typescript
const API_URL = 'http://identity-vessel.activity-system.svc.cluster.local:8080';

async function login(email: string, password: string) {
  const response = await fetch(`${API_URL}/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });

  const data = await response.json();

  if (data.success) {
    localStorage.setItem('authToken', data.token);
    setUser(data.user);
    setIsAuthenticated(true);
  } else {
    throw new Error(data.error);
  }
}
```

### Phase 4: Add SurrealDB Connection to Identity Vessel

**File:** `repos/identity-vessel/src/db/surrealdb.ts`

```typescript
import Surreal from 'surrealdb.js';

const SURREALDB_URL = process.env.SURREALDB_URL || 'http://surrealdb.activity-system.svc.cluster.local:8000';
const SURREALDB_NAMESPACE = process.env.SURREALDB_NAMESPACE || 'activity-system';
const SURREALDB_DATABASE = process.env.SURREALDB_DATABASE || 'learning_loop';
const SURREALDB_USERNAME = process.env.SURREALDB_USERNAME || 'root';
const SURREALDB_PASSWORD = process.env.SURREALDB_PASSWORD || 'root';

let db: Surreal | null = null;

export async function connectToSurrealDB(): Promise<Surreal> {
  if (db) return db;

  db = new Surreal();

  await db.connect(SURREALDB_URL);
  await db.signin({
    username: SURREALDB_USERNAME,
    password: SURREALDB_PASSWORD
  });
  await db.use({
    namespace: SURREALDB_NAMESPACE,
    database: SURREALDB_DATABASE
  });

  console.log('[SurrealDB] Connected');

  return db;
}
```

---

## Benefits of This Architecture

### 1. Single Source of Truth
- All authentication logic in one place
- Easier to audit for security
- Consistent behavior across all services

### 2. Vessels Delegate to Vessels
- Activity-api delegates auth to identity-vessel
- Concept-db delegates auth to identity-vessel
- Cloud dashboard delegates auth to identity-vessel
- **Proper vessel pattern**

### 3. Easier to Extend
- Add OAuth? Just add to identity-vessel
- Add MFA? Just add to identity-vessel
- Add SSO? Just add to identity-vessel

### 4. Better Trace Collection
- All authentication operations traced
- Can see: login attempts, API key usage, failures
- Learning about authentication patterns

---

## Summary

**Current State:**
- ✅ Identity vessel handles API key auth
- ❌ Identity vessel doesn't handle login yet

**Correct Architecture:**
- Identity vessel handles **ALL** authentication:
  - Username/password login
  - API key validation
  - JWT session tokens
  - Future: OAuth, SSO, MFA

**Next Steps:**
1. Add SurrealDB connection to identity-vessel
2. Add login/signup/me endpoints
3. Update `/v1/auth/resolve` to handle both JWT and API keys
4. Update dashboard to call identity-vessel (not activity-api)
5. Test end-to-end login flow

**Estimate:** ~3-4 hours to implement and test
