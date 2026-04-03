# Authentication Flow Diagrams

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Metabob Platform                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐                  ┌──────────────┐        │
│  │   Browser    │                  │   IDE/CLI    │        │
│  │   Users      │                  │    Tools     │        │
│  └──────┬───────┘                  └──────┬───────┘        │
│         │                                 │                │
│         │ email/password                  │ API Key        │
│         ▼                                 ▼                │
│  ┌─────────────────┐            ┌──────────────────┐      │
│  │  Session Auth   │            │  API Key Auth    │      │
│  │     (JWT)       │            │     (HMAC)       │      │
│  └────────┬────────┘            └────────┬─────────┘      │
│           │                              │                │
│           ▼                              ▼                │
│  ┌──────────────────────────────────────────────┐        │
│  │        metabob-activity-api                  │        │
│  │  (validates JWT, calls identity-vessel)      │        │
│  └──────────────────┬───────────────────────────┘        │
│                     │                                     │
│                     ▼                                     │
│            ┌─────────────────┐                           │
│            │ identity-vessel │                           │
│            │  (validates     │                           │
│            │   API keys)     │                           │
│            └─────────────────┘                           │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

---

## Flow 1: Dashboard User Login (Session Auth)

```
┌─────────┐
│ Browser │
│  User   │
└────┬────┘
     │
     │ 1. Navigate to app.metabob.local
     ▼
┌──────────────────┐
│ Cloud Dashboard  │
│  Login Page      │
└────┬─────────────┘
     │
     │ 2. Enter credentials
     │    email: avi@metabob.com
     │    password: ********
     ▼
     POST /v2/auth/login
     {
       "email": "avi@metabob.com",
       "password": "********"
     }
     │
     ▼
┌──────────────────────────┐
│ metabob-activity-api     │
│                          │
│ 1. Query SurrealDB:      │
│    SELECT * FROM users   │
│    WHERE email = $email  │
│                          │
│ 2. Verify password:      │
│    crypto::argon2::      │
│    compare($hash, $pw)   │
│                          │
│ 3. Generate JWT:         │
│    {                     │
│      userId: "usr_avi",  │
│      orgId: "metabob_com"│
│      exp: <15min>        │
│    }                     │
└──────────┬───────────────┘
           │
           │ Response:
           │ {
           │   "token": "eyJhbGci...",
           │   "user": {...}
           │ }
           ▼
┌──────────────────┐
│ Cloud Dashboard  │
│                  │
│ 1. Store token:  │
│    localStorage. │
│    setItem(...)  │
│                  │
│ 2. Redirect to   │
│    /dashboard    │
└──────────────────┘
```

---

## Flow 2: Dashboard API Request (With Session)

```
┌─────────┐
│ Browser │
│  User   │
└────┬────┘
     │
     │ Click "View Projects"
     ▼
┌──────────────────┐
│ Cloud Dashboard  │
└────┬─────────────┘
     │
     │ GET /api/v2/projects
     │ Authorization: Bearer eyJhbGci...  (JWT)
     ▼
┌──────────────────────────┐
│ metabob-activity-api     │
│                          │
│ Middleware:              │
│                          │
│ 1. Extract JWT token     │
│ 2. Verify signature      │
│ 3. Check expiration      │
│ 4. Extract claims:       │
│    {                     │
│      userId: "usr_avi",  │
│      orgId: "metabob_com"│
│    }                     │
│ 5. Set auth context      │
│                          │
│ Query:                   │
│ SELECT * FROM projects   │
│ WHERE org_id = $orgId    │
└──────────┬───────────────┘
           │
           │ Response:
           │ {
           │   "projects": [...]
           │ }
           ▼
┌──────────────────┐
│ Cloud Dashboard  │
│ Shows projects   │
└──────────────────┘
```

---

## Flow 3: Generate API Key (Bridging Both Systems)

```
┌─────────┐
│ Browser │
│  User   │
└────┬────┘
     │ (Already logged in with JWT)
     │
     │ Navigate to Settings → API Keys
     ▼
┌──────────────────┐
│ Cloud Dashboard  │
│ API Keys Page    │
└────┬─────────────┘
     │
     │ Click "Generate New Key"
     │ Fill form:
     │   Name: "My IDE Key"
     │   Scopes: [read, write]
     │   Expires: 365 days
     ▼
     POST /api/auth/proxy/identity-vessel/v1/keys/generate
     Authorization: Bearer eyJhbGci...  (JWT session)
     {
       "name": "My IDE Key",
       "scopes": ["read", "write"],
       "expiresInDays": 365
     }
     │
     ▼
┌──────────────────────────┐
│ metabob-activity-api     │
│ (Proxy endpoint)         │
│                          │
│ 1. Validate JWT session  │
│ 2. Extract userId/orgId  │
│ 3. Get admin API key     │
│    for this org          │
└──────────┬───────────────┘
           │
           │ POST http://identity-vessel:8080/v1/keys/generate
           │ Authorization: Bearer <admin-api-key>
           │ {
           │   "targetUserId": "usr_avi",
           │   "name": "My IDE Key",
           │   "scopes": ["read", "write"],
           │   "expiresInDays": 365
           │ }
           ▼
┌─────────────────────────────┐
│ identity-vessel             │
│                             │
│ 1. Validate admin API key   │
│ 2. Generate new key:        │
│    - Create keyId           │
│    - Sign with HMAC         │
│    - Base64 encode          │
│                             │
│ 3. Store metadata:          │
│    INSERT INTO api_key {    │
│      keyId, orgId, userId,  │
│      name, scopes, ...      │
│    }                        │
│                             │
│ 4. Return key (ONLY TIME!)  │
└──────────┬──────────────────┘
           │
           │ Response:
           │ {
           │   "key": "bWJfdGVzdC1tZXRh...",
           │   "keyId": "key_abc123",
           │   "metadata": {...}
           │ }
           ▼
┌──────────────────────────┐
│ metabob-activity-api     │
│ (returns to dashboard)   │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────┐
│ Cloud Dashboard  │
│                  │
│ Shows modal:     │
│ ┌──────────────┐│
│ │ Copy API Key ││
│ │              ││
│ │ bWJfdGVzdC... ││
│ │              ││
│ │   [Copy]     ││
│ └──────────────┘│
│                  │
│ ⚠️ Key shown     │
│   ONCE only!     │
└──────────────────┘
```

---

## Flow 4: IDE API Request (With API Key)

```
┌─────────┐
│   IDE   │
│  (VSCode│
│ Plugin) │
└────┬────┘
     │
     │ Config file:
     │ {
     │   "apiKey": "bWJfdGVzdC1tZXRh..."
     │ }
     │
     │ Request code analysis
     ▼
     GET https://api.metabob.com/v2/analysis/scan
     Authorization: Bearer bWJfdGVzdC1tZXRh...  (API Key)
     │
     ▼
┌──────────────────────────┐
│ metabob-activity-api     │
│                          │
│ Middleware:              │
│                          │
│ 1. Extract token         │
│ 2. Detect: NOT a JWT     │
│    (doesn't start eyJ)   │
│ 3. Assume API key        │
└──────────┬───────────────┘
           │
           │ POST http://identity-vessel:8080/v1/auth/resolve
           │ {
           │   "impulse": {
           │     "type": "authentication",
           │     "pointer": {
           │       "type": "apiKey",
           │       "apiKey": "bWJfdGVzdC1tZXRh..."
           │     }
           │   }
           │ }
           ▼
┌─────────────────────────────┐
│ identity-vessel             │
│                             │
│ 1. Decode base64            │
│ 2. Parse components:        │
│    - prefix: mb_test        │
│    - orgId: metabob_com     │
│    - userId: usr_avi        │
│    - keyId: key_abc123      │
│    - signature: 79cd41...   │
│                             │
│ 3. Verify HMAC signature    │
│    (constant-time)          │
│                             │
│ 4. Check Redis revocation:  │
│    GET revoked:key_abc123   │
│    → nil (not revoked)      │
│                             │
│ 5. Return auth context      │
└──────────┬──────────────────┘
           │
           │ Response:
           │ {
           │   "authenticated": true,
           │   "orgId": "metabob_com",
           │   "userId": "usr_avi",
           │   "keyId": "key_abc123",
           │   "scopes": ["read", "write"]
           │ }
           ▼
┌──────────────────────────┐
│ metabob-activity-api     │
│                          │
│ Set auth context:        │
│ c.set('auth', {          │
│   orgId: "metabob_com",  │
│   userId: "usr_avi",     │
│   type: "api_key"        │
│ })                       │
│                          │
│ Process request with     │
│ org isolation            │
└──────────┬───────────────┘
           │
           │ Response:
           │ {
           │   "results": [...]
           │ }
           ▼
┌─────────┐
│   IDE   │
│ Shows   │
│ results │
└─────────┘
```

---

## Decision Tree: Which Auth Method?

```
Request received
│
├─ Is this from a browser?
│  │
│  ├─ YES → Check for session cookie
│  │       │
│  │       ├─ Cookie exists → Use JWT session
│  │       └─ No cookie → Redirect to /login
│  │
│  └─ NO → Check Authorization header
│          │
│          ├─ Header exists
│          │  │
│          │  ├─ Starts with "eyJ" → JWT token
│          │  │  → Verify JWT signature
│          │  │
│          │  └─ Doesn't start "eyJ" → API key
│          │     → Call identity-vessel
│          │
│          └─ No header → 401 Unauthorized
│
└─ Auth context populated
   → Process request
```

---

## Summary Table

| Aspect | Session (Dashboard) | API Key (IDE) |
|--------|-------------------|---------------|
| **Initial Auth** | POST /v2/auth/login<br>email + password | Already has key<br>(generated from dashboard) |
| **Token Format** | JWT<br>`eyJhbGci...` | Base64 HMAC<br>`bWJfdGVzdC1tZXRh...` |
| **Validation** | JWT signature check<br>(in-process) | HTTP call to<br>identity-vessel |
| **Latency** | ~10μs<br>(crypto verify) | ~7ms<br>(HTTP roundtrip) |
| **Handler** | metabob-activity-api | identity-vessel |
| **Storage** | None (stateless) | Metadata only<br>(SurrealDB) |
| **Expiration** | 15 minutes | 1 year |
| **Revocation** | Expires naturally | Immediate (Redis) |
| **Use Case** | Human → Browser → API | Tool → API |

---

## Key Takeaways

1. **Two independent systems** - Session auth and API key auth don't overlap
2. **Identity vessel = API keys only** - Doesn't handle username/password
3. **Session auth = elsewhere** - Handled by metabob-activity-api (or analysis-api)
4. **They connect via dashboard** - Users log in with session, generate API keys for their tools
5. **Services support both** - Backend APIs validate either JWT or API key

The identity-vessel is a **specialized authentication vessel** for programmatic access only.
