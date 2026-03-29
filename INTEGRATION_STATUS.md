# Integration Status: Cloud Dashboard + Identity Vessel

## Current State

### ✅ Complete

1. **Identity Vessel** - API key authentication
   - Base64-encoded HMAC keys
   - Fast validation (<7ms)
   - Fire-and-forget trace collection
   - Redis revocation cache
   - Complete test suite

2. **Cloud Dashboard** - Frontend
   - Accessible at `http://app.metabob.local`
   - React 19 + TypeScript
   - UI components ready

3. **metabob-activity-api** - Backend
   - Running in Kubernetes
   - Health endpoints working
   - SurrealDB connected

### ❌ Missing

1. **Username/Password Auth Endpoints**
   - `POST /v2/auth/login` - Not implemented
   - `POST /v2/auth/signup` - Not implemented
   - `GET /v2/auth/me` - Not implemented
   - `PUT /v2/auth/password` - Not implemented

2. **API Key Proxy Endpoint**
   - `POST /api/auth/proxy/identity-vessel/v1/keys/generate` - Not implemented
   - `POST /api/auth/proxy/identity-vessel/v1/keys/revoke/:keyId` - Not implemented
   - `GET /api/auth/proxy/identity-vessel/v1/keys` - Not implemented

3. **SurrealDB Schema**
   - `users` table - Not created
   - `organizations` table - Not created
   - `api_key` metadata table - Not created

---

## What Works Right Now

### Direct API Key Generation (Without Dashboard)

You can generate and test API keys directly:

```bash
cd /home/avi/documents/work/exp-repo/metabob-devbob/repos/identity-vessel

# 1. Start identity-vessel
export API_KEY_SECRET="test-secret-for-development-min-32-chars-long"
export PORT=8181
bun run src/index.ts &

# 2. Generate an API key
API_KEY=$(API_KEY_SECRET="test-secret-for-development-min-32-chars-long" bun -e "
import { generateApiKey } from './src/services/keyGeneration.ts';
const result = generateApiKey('metabob_com', 'usr_avi', {
  name: 'Test Key',
  scopes: ['read', 'write'],
  expiresInDays: 365
});
console.log(result.key);
")

echo "Your API Key: $API_KEY"

# 3. Test the key
curl -X POST http://localhost:8181/v1/auth/resolve \
  -H 'Content-Type: application/json' \
  -d "{
    \"impulse\": {
      \"type\": \"authentication\",
      \"pointer\": {
        \"type\": \"apiKey\",
        \"apiKey\": \"$API_KEY\"
      }
    }
  }"
```

This works! You get a valid API key that can be used for programmatic access.

---

## What Needs To Be Built

### Phase 1: Auth Endpoints in metabob-activity-api

Create these routes in `repos/metabob-activity-api/src/routes/auth.ts`:

```typescript
import { Hono } from 'hono';
import { z } from 'zod';
import { sign, verify } from 'hono/jwt';

const authRoutes = new Hono();
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';

// Login
authRoutes.post('/login', async (c) => {
  const { email, password } = await c.req.json();

  // Query SurrealDB for user
  const users = await db.query(`
    SELECT * FROM users
    WHERE email = $email
    LIMIT 1
  `, { email });

  if (!users || users.length === 0) {
    return c.json({ error: 'Invalid credentials' }, 401);
  }

  const user = users[0];

  // Verify password (Argon2)
  const valid = await db.query(`
    RETURN crypto::argon2::compare($hash, $password)
  `, {
    hash: user.password_hash,
    password
  });

  if (!valid[0]) {
    return c.json({ error: 'Invalid credentials' }, 401);
  }

  // Generate JWT
  const token = await sign({
    userId: user.id,
    orgId: user.org_id,
    email: user.email,
    exp: Math.floor(Date.now() / 1000) + (15 * 60) // 15 min
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

// Signup
authRoutes.post('/signup', async (c) => {
  const { email, password, name, orgName } = await c.req.json();

  // Hash password
  const passwordHash = await db.query(`
    RETURN crypto::argon2::generate($password)
  `, { password });

  // Create org
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
authRoutes.get('/me', async (c) => {
  const authHeader = c.req.header('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return c.json({ error: 'Missing Authorization header' }, 401);
  }

  const token = authHeader.slice(7);
  const payload = await verify(token, JWT_SECRET);

  return c.json({
    success: true,
    user: {
      id: payload.userId,
      email: payload.email,
      orgId: payload.orgId
    }
  });
});

export default authRoutes;
```

### Phase 2: API Key Proxy Endpoints

Create proxy routes that validate session tokens and call identity-vessel:

```typescript
authRoutes.post('/proxy/identity-vessel/*', async (c) => {
  // 1. Validate session token
  const authHeader = c.req.header('Authorization');
  const token = authHeader?.slice(7);
  const payload = await verify(token, JWT_SECRET);

  // 2. Generate admin API key for this org
  const adminKey = await getOrgAdminKey(payload.orgId);

  // 3. Proxy to identity-vessel
  const vesselPath = c.req.param('*');
  const response = await fetch(`http://identity-vessel:8080/${vesselPath}`, {
    method: c.req.method,
    headers: {
      'Authorization': `Bearer ${adminKey}`,
      'Content-Type': 'application/json'
    },
    body: await c.req.text()
  });

  return response;
});
```

### Phase 3: SurrealDB Schema

Create migration: `repos/metabob-activity-api/sql/migrations/060-auth-schema.surql`

```surql
-- Organizations table
DEFINE TABLE organizations SCHEMAFULL;
DEFINE FIELD name ON organizations TYPE string;
DEFINE FIELD created_at ON organizations TYPE datetime;
DEFINE INDEX org_name ON organizations FIELDS name UNIQUE;

-- Users table
DEFINE TABLE users SCHEMAFULL;
DEFINE FIELD email ON users TYPE string;
DEFINE FIELD password_hash ON users TYPE string;
DEFINE FIELD name ON users TYPE string;
DEFINE FIELD org_id ON users TYPE record<organizations>;
DEFINE FIELD created_at ON users TYPE datetime;
DEFINE INDEX user_email ON users FIELDS email UNIQUE;

-- API keys metadata table
DEFINE TABLE api_key SCHEMAFULL;
DEFINE FIELD id ON api_key TYPE string;  -- key_abc123
DEFINE FIELD org_id ON api_key TYPE record<organizations>;
DEFINE FIELD user_id ON api_key TYPE record<users>;
DEFINE FIELD name ON api_key TYPE string;
DEFINE FIELD key_prefix ON api_key TYPE string;  -- mb_live or mb_test
DEFINE FIELD scopes ON api_key TYPE array<string>;
DEFINE FIELD created_at ON api_key TYPE datetime;
DEFINE FIELD expires_at ON api_key TYPE datetime;
DEFINE FIELD is_active ON api_key TYPE bool;
DEFINE FIELD last_used ON api_key TYPE datetime;
DEFINE FIELD usage_count ON api_key TYPE int DEFAULT 0;

-- Bootstrap default org and user
LET $metabob_org = (SELECT * FROM organizations WHERE name = 'Metabob' LIMIT 1);
IF $metabob_org == [] THEN
  CREATE organizations:metabob_com SET
    name = 'Metabob',
    created_at = time::now();
END;

LET $avi_user = (SELECT * FROM users WHERE email = 'avi@metabob.com' LIMIT 1);
IF $avi_user == [] THEN
  CREATE users:avi SET
    email = 'avi@metabob.com',
    password_hash = crypto::argon2::generate('password123'),
    name = 'Avi',
    org_id = organizations:metabob_com,
    created_at = time::now();
END;
```

### Phase 4: Dashboard UI Updates

Update `repos/metabob-cloud-dashboard/src/pages/Settings.tsx`:

```typescript
// Add API Keys tab
<Tab label="API Keys" />

// In API Keys tab content:
<div>
  <h2>API Keys</h2>
  <button onClick={() => setShowGenerateModal(true)}>
    Generate New Key
  </button>

  <table>
    <thead>
      <tr>
        <th>Name</th>
        <th>Prefix</th>
        <th>Scopes</th>
        <th>Created</th>
        <th>Expires</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
      {apiKeys.map(key => (
        <tr key={key.keyId}>
          <td>{key.name}</td>
          <td>{key.prefix}-****</td>
          <td>{key.scopes.join(', ')}</td>
          <td>{formatDate(key.createdAt)}</td>
          <td>{formatDate(key.expiresAt)}</td>
          <td>
            <button onClick={() => revokeKey(key.keyId)}>
              Revoke
            </button>
          </td>
        </tr>
      ))}
    </tbody>
  </table>
</div>
```

---

## Quick Start: Test What Works Now

```bash
# Clone this test script
cd /home/avi/documents/work/exp-repo/metabob-devbob/repos/identity-vessel

# Run the direct API key test
./test-endpoints.sh

# You'll get a working API key that can be used immediately
```

---

## Estimated Work Remaining

| Task | Effort | Priority |
|------|--------|----------|
| Auth endpoints (login/signup/me) | 2-3 hours | HIGH |
| API key proxy endpoints | 1 hour | HIGH |
| SurrealDB schema migration | 30 min | HIGH |
| Dashboard API Keys UI | 2-3 hours | MEDIUM |
| Integration testing | 1 hour | MEDIUM |
| **Total** | **~7-8 hours** | |

---

## Summary

**What we have:**
- ✅ Identity vessel (complete, tested, working)
- ✅ Cloud dashboard frontend (running)
- ✅ Backend infrastructure (Kubernetes, SurrealDB)

**What we need:**
- ❌ Username/password auth endpoints
- ❌ API key proxy endpoints
- ❌ Database schema for users/orgs
- ❌ Dashboard UI for key management

**Workaround for now:**
- Generate API keys directly via script (works perfectly!)
- Use API keys for programmatic access
- Build auth endpoints next to enable dashboard login
