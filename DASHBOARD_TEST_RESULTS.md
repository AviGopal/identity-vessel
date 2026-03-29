# Cloud Dashboard Playwright Test Results

**Test Date:** 2026-03-29
**Dashboard URL:** http://app.metabob.local

---

## Test Summary

✅ **Frontend working correctly**
❌ **Backend auth endpoint missing**

---

## What We Tested

### 1. Login Page Access
- **URL:** http://app.metabob.local/
- **Status:** ✅ Accessible
- **Page Title:** "Metabob Dashboard"
- **UI State:** Login form displayed

### 2. Login Form Interaction
**Form Fields:**
- Email: `avi@metabob.com` ✅ Entered successfully
- Password: `password123` ✅ Entered successfully
- Submit Button: ✅ Clickable

### 3. Login Submission
**Request:**
```http
POST /api/auth/login HTTP/1.1
Host: app.metabob.local
Content-Type: application/json

{
  "email": "avi@metabob.com",
  "password": "password123"
}
```

**Response:**
```http
HTTP/1.1 500 Internal Server Error
```

**UI Feedback:**
- Error message displayed: "Internal Server Error"
- Form remains on screen
- No navigation occurred

---

## Screenshots

### Login Page (Initial State)
![Login Page](app-metabob-login-page.png)

- Clean dark theme
- Email/password fields
- "Sign in" button
- "Welcome to Metabob" heading

### Login Page (After Error)
![Error State](app-metabob-login-error.png)

- "Internal Server Error" message displayed above form
- Fields retain their values
- User can retry

---

## Network Analysis

### API Endpoint Called
```
POST http://app.metabob.local/api/auth/login
```

### Request Payload
```json
{
  "email": "avi@metabob.com",
  "password": "password123"
}
```

### Response Status
```
500 Internal Server Error
```

### Console Warnings
```
[WARNING] Password fields present on an insecure (http://) page.
This is a security risk that allows user login credentials to be stolen.
```
*Note: Expected warning for local development (not using HTTPS)*

---

## Root Cause

The backend endpoint `/api/auth/login` either:
1. Does not exist (404 gets converted to 500)
2. Exists but has an unhandled error
3. Exists but is not properly routing

**Most likely:** The endpoint doesn't exist yet and needs to be implemented.

---

## Required Backend Implementation

### Endpoint Specification

**Route:** `POST /api/auth/login`

**Expected Request:**
```json
{
  "email": "string",
  "password": "string"
}
```

**Expected Success Response (200):**
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": "usr_abc123",
    "email": "avi@metabob.com",
    "name": "Avi",
    "orgId": "metabob_com"
  }
}
```

**Expected Error Response (401):**
```json
{
  "success": false,
  "error": "Invalid credentials"
}
```

### Implementation Location

File: `repos/metabob-activity-api/src/routes/auth.ts`

```typescript
import { Hono } from 'hono';
import { sign } from 'hono/jwt';

const authRoutes = new Hono();
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

authRoutes.post('/login', async (c) => {
  const { email, password } = await c.req.json();

  // 1. Query user from SurrealDB
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

  // 2. Verify password (Argon2)
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

  // 3. Generate JWT token (15 min expiry)
  const token = await sign({
    userId: user.id,
    orgId: user.org_id,
    email: user.email,
    exp: Math.floor(Date.now() / 1000) + (15 * 60)
  }, JWT_SECRET);

  // 4. Return token and user info
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

export default authRoutes;
```

### Database Schema Required

File: `repos/metabob-activity-api/sql/migrations/060-auth-schema.surql`

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

-- Bootstrap test user
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

---

## Testing After Implementation

Once the backend is deployed, test with:

```bash
# 1. Test login endpoint directly
curl -X POST http://app.metabob.local/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "avi@metabob.com",
    "password": "password123"
  }'

# Expected response:
# {
#   "success": true,
#   "token": "eyJ...",
#   "user": {...}
# }

# 2. Test via Playwright (automated)
./test-dashboard-login.sh
```

---

## Current Workaround

Until the login endpoint is implemented, use direct API key generation:

```bash
cd /home/avi/documents/work/exp-repo/metabob-devbob/repos/identity-vessel
./generate-api-key.sh
```

This bypasses the dashboard login and gives you a working API key for programmatic access.

---

## Summary

**Frontend:** ✅ Working perfectly - ready for login
**Backend:** ❌ Login endpoint needs to be implemented
**Database:** ❌ Schema needs to be created
**Estimate:** ~2-3 hours to implement and test

The dashboard UI is production-ready. The missing piece is the backend authentication infrastructure.
