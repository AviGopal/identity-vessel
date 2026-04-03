# Vessel Separation of Concerns

Based on the foundational principle: **Resolvers live where data lives.**

## Core Vessels (Deployed)

### 1. **identity-vessel** (Authentication & Authorization Vessel)

**Purpose**: Validate identity and permissions. Manage authentication credentials.

**Owns**:
- `users` table (authentication credentials)
- `organizations` table (tenant boundaries)
- `api_keys` table (authentication tokens)

**Responsibilities**:
- ✅ User authentication (login with email/password)
- ✅ API key generation (create, revoke, validate)
- ✅ API key validation (HMAC signature verification)
- ✅ JWT token generation for sessions
- ✅ Organization membership queries (is user in org?)
- ✅ Permission checks (does this key have scope X?)

**Does NOT**:
- ❌ Track connections or sessions (that's activity-api)
- ❌ Track activity executions (that's activity-api)
- ❌ Compute costs (that's activity-api)
- ❌ Manage projects (that's analysis-api or project-vessel)

**Endpoints**:
- `POST /v1/auth/login` - Email/password authentication
- `POST /v1/auth/signup` - User registration
- `POST /v1/auth/resolve` - Validate API key or JWT
- `GET /v1/auth/me` - Get current user from token
- `POST /v1/keys/generate` - Create new API key
- `DELETE /v1/keys/:id` - Revoke API key
- `GET /v1/keys` - List user's API keys (metadata only)
- `PATCH /v1/keys/:id` - Update key tier/limits
- `GET /v1/orgs/:id` - Get organization details
- `GET /v1/orgs/:id/members` - List organization members

**Output**: Authentication impulses
```typescript
{
  type: "authentication",
  authenticated: true,
  orgId: "organizations:metabob_com",
  userId: "users:abc123",
  keyId: "api_keys:xyz789",  // if API key auth
  email: "avi@metabob.com",  // if JWT auth
  scopes: ["read", "write"]
}
```

---

### 2. **metabob-activity-api** (Activity Execution & Lifecycle Vessel)

**Purpose**: Track activity executions, connections, and operational metrics.

**Owns**:
- `activity_template` table (activity definitions)
- `activity_execution` table (execution traces with state)
- `active_connections` table (which instances are running)
- `activity_executions` table (cost/performance tracking)
- `cost_summaries` table (aggregated metrics)

**Responsibilities**:
- ✅ Store activity templates
- ✅ Thompson Sampling for template selection
- ✅ Store execution traces (impulses used, tools called, state transitions)
- ✅ Connection lifecycle management (establish, heartbeat, disconnect)
- ✅ Track which instances are active with which keys
- ✅ Record activity costs (LLM tokens, USD)
- ✅ Aggregate cost summaries (by org/project/goal/time)
- ✅ Enforce connection limits (key-level and org-level)
- ✅ Clean up stale connections

**Does NOT**:
- ❌ Validate authentication (delegates to identity-vessel)
- ❌ Generate API keys (that's identity-vessel)
- ❌ Manage users or organizations (that's identity-vessel)

**Endpoints**:
- `GET /v2/activities/templates` - List activity templates
- `POST /v2/activities/recommend` - Thompson Sampling recommendations
- `POST /v2/activities/execution-traces` - Store execution trace
- `GET /v2/activities/execution-traces` - Query execution history
- `POST /v2/connections/establish` - Establish connection (checks quotas)
- `POST /v2/connections/heartbeat` - Update heartbeat
- `POST /v2/connections/disconnect` - Clean disconnect
- `GET /v2/connections` - List active connections (org or key)
- `POST /v2/activities/start` - Record activity start
- `POST /v2/activities/complete` - Record activity completion with costs
- `GET /v2/costs/org/:id` - Organization costs
- `GET /v2/costs/org/:id/projects` - Cost by project
- `GET /v2/costs/org/:id/goals` - Cost by goal
- `GET /v2/costs/org/:id/timeline` - Cost over time

**Authentication Middleware**:
```typescript
app.use('/v2/*', async (c, next) => {
  const authHeader = c.req.header('Authorization');
  const token = authHeader?.replace('Bearer ', '');

  // Delegate to identity-vessel for validation
  const authResult = await fetch('http://identity-vessel:8080/v1/auth/resolve', {
    method: 'POST',
    body: JSON.stringify({
      impulse: {
        type: 'authentication',
        pointer: { type: token.startsWith('eyJ') ? 'jwt' : 'apiKey', token }
      }
    })
  });

  const { authenticated, orgId, userId } = await authResult.json();

  if (!authenticated) return c.json({ error: 'Unauthorized' }, 401);

  c.set('orgId', orgId);
  c.set('userId', userId);
  await next();
});
```

---

### 3. **concept-db** (Concept Storage & Lifecycle Vessel)

**Purpose**: Store and manage concepts, edges, sequences, and their lifecycle hooks.

**Owns**:
- `concept` table
- `concept_edge` table
- `concept_sequence` table
- `concept_usage` table
- Lifecycle hooks (creation, mutation, deletion)

**Responsibilities**:
- ✅ Store concepts with embeddings
- ✅ Store relationships between concepts (edges)
- ✅ Store sequences (ordered concept chains)
- ✅ Execute lifecycle hooks (upkeep activities)
- ✅ Trigger thompson sampling for hook execution
- ✅ Track concept usage patterns

**Does NOT**:
- ❌ Authenticate users (delegates to identity-vessel)
- ❌ Track activity costs (that's activity-api)
- ❌ Manage connections (that's activity-api)

**Endpoints**:
- `POST /v1/concepts` - Create concept
- `GET /v1/concepts/:id` - Get concept by ID
- `GET /v1/concepts` - Query concepts (with filters)
- `POST /v1/concepts/:id/edges` - Create edge
- `GET /v1/concepts/:id/edges` - Get concept relationships
- `POST /v1/sequences` - Create sequence
- `GET /v1/sequences/:id` - Get sequence
- `POST /v1/upkeep/trigger` - Manually trigger lifecycle hooks

---

### 4. **metabob-cloud-dashboard** (Web UI Vessel)

**Purpose**: User interface for humans. Proxies to backend vessels.

**Owns**: No tables (frontend only)

**Responsibilities**:
- ✅ Render UI for authentication (login/signup)
- ✅ Proxy auth requests to identity-vessel
- ✅ Proxy API key management to identity-vessel
- ✅ Proxy activity data to activity-api
- ✅ Proxy connection data to activity-api
- ✅ Proxy cost data to activity-api
- ✅ Display real-time dashboards

**Routing**:
```typescript
// Auth → identity-vessel
if (pathname.startsWith('/api/auth/')) {
  proxy to: http://identity-vessel:8080/v1/auth/...
}

// API keys → identity-vessel
if (pathname.startsWith('/api/keys/')) {
  proxy to: http://identity-vessel:8080/v1/keys/...
}

// Activity, connections, costs → activity-api
if (pathname.startsWith('/api/v2/')) {
  proxy to: http://metabob-activity-api:8080/v2/...
}
```

---

## Additional Vessels (Not Deployed)

### 5. **metabob-analysis-api** (Code Analysis Vessel)

**Purpose**: Static analysis, problem detection, CPG operations.

**Owns**:
- `projects` table
- `problems` table (detected issues)
- `analysis_results` table
- CPG graphs

**Responsibilities**:
- ✅ Analyze code repositories
- ✅ Detect problems (bugs, security issues, code quality)
- ✅ Store analysis results
- ✅ Manage projects
- ✅ Serve CPG data

**Should NOT have**: Auth endpoints (that's identity-vessel)

---

### 6. **user-vessel** (User Preferences & Settings Vessel)

**Purpose**: User-specific configuration and preferences.

**Owns**:
- `user_preferences` table
- `user_settings` table
- `user_notifications` table

**Responsibilities**:
- ✅ Store user preferences (theme, language, notification settings)
- ✅ Manage user notification subscriptions
- ✅ Track user onboarding state

---

### 7. **minibob** (Autonomous Development Vessel)

**Purpose**: Execute activities autonomously.

**Owns**: Nothing! MiniBob is a client, not a data store.

**Responsibilities**:
- ✅ Execute activities with LLM
- ✅ Call tools (bash, read, write, edit, git)
- ✅ Report executions to activity-api
- ✅ Maintain connection heartbeat to activity-api
- ✅ Resolve LOCAL impulses (memo, file)
- ✅ Delegate to activity-api for remote impulses

**Connection Lifecycle**:
```typescript
// 1. On startup
const { connection_id } = await fetch('http://activity-api/v2/connections/establish', {
  method: 'POST',
  headers: { 'Authorization': `Bearer ${API_KEY}` },
  body: JSON.stringify({
    instance_id: INSTANCE_ID,
    instance_type: 'minibob',
    client_metadata: { version: '1.0.0', platform: 'linux' }
  })
});

// 2. Every 60 seconds
await fetch('http://activity-api/v2/connections/heartbeat', {
  method: 'POST',
  body: JSON.stringify({ connection_id })
});

// 3. Before starting activity
await fetch('http://activity-api/v2/activities/start', {
  method: 'POST',
  body: JSON.stringify({
    connection_id,
    execution_id: uuid(),
    activity_template_id: template.id,
    project_id: context.project_id,
    goal_description: goal
  })
});

// 4. After activity completes
await fetch('http://activity-api/v2/activities/complete', {
  method: 'POST',
  body: JSON.stringify({
    execution_id,
    status: 'completed',
    duration_ms: elapsed,
    cost_usd: calculateCost(),
    llm_tokens_used: totalTokens,
    tool_calls_count: toolCalls.length
  })
});

// 5. On shutdown
await fetch('http://activity-api/v2/connections/disconnect', {
  method: 'POST',
  body: JSON.stringify({ connection_id })
});
```

---

## Data Flow Examples

### Example 1: User logs in and creates API key

```
1. User enters credentials in dashboard
   → POST app.metabob.local/api/auth/login

2. Dashboard proxies to identity-vessel
   → POST identity-vessel:8080/v1/auth/login
   ← Returns JWT token

3. User navigates to API Keys page
   → Dashboard shows UI

4. User clicks "Create Key"
   → POST app.metabob.local/api/keys
   → Proxied to identity-vessel:8080/v1/keys/generate
   ← Returns API key (shown once!)

5. Dashboard displays key: mb_live_abc123...
```

### Example 2: MiniBob connects and runs activity

```
1. MiniBob starts with API key
   → POST activity-api:8080/v2/connections/establish
   → Headers: Authorization: Bearer mb_live_abc123...

2. activity-api validates key
   → POST identity-vessel:8080/v1/auth/resolve
   ← { authenticated: true, orgId, userId, keyId }

3. activity-api checks quotas
   → SELECT current_connections FROM api_keys WHERE key_id = ...
   → SELECT current_active_connections FROM organizations WHERE id = ...
   → If within limits: Create active_connections record
   ← { connection_id, quota_remaining }

4. MiniBob receives goal "Fix bug in auth.ts"
   → POST activity-api:8080/v2/activities/start
   → { connection_id, execution_id, activity_template_id, goal }

5. MiniBob executes activity with LLM and tools
   → Calls bash, read, write, git tools
   → Tracks cost, tokens, tool calls

6. MiniBob completes activity
   → POST activity-api:8080/v2/activities/complete
   → { execution_id, status, duration_ms, cost_usd, llm_tokens_used }

7. activity-api updates cost tracking
   → INSERT INTO activity_executions (...)
   → Triggers cost aggregation job
```

### Example 3: User views cost dashboard

```
1. User navigates to Cost page in dashboard
   → GET app.metabob.local/api/v2/costs/org/:id/projects

2. Dashboard proxies to activity-api
   → GET activity-api:8080/v2/costs/org/:id/projects
   → Headers: Authorization: Bearer <JWT>

3. activity-api validates JWT
   → POST identity-vessel:8080/v1/auth/resolve
   ← { authenticated: true, orgId, userId }

4. activity-api queries cost data
   → SELECT project_id, SUM(cost_usd), COUNT(*)
     FROM activity_executions
     WHERE org_id = :orgId
     GROUP BY project_id

5. activity-api returns aggregated data
   ← [
       { project_id: "my-app", cost: 127.45, executions: 1523 },
       { project_id: "cli-tool", cost: 42.30, executions: 456 }
     ]

6. Dashboard renders cost breakdown chart
```

---

## Key Architectural Decisions

### 1. **Identity-vessel does NOT track connections**
- ❌ Wrong: identity-vessel owns `active_connections` table
- ✅ Right: activity-api owns `active_connections` table
- **Reason**: Connections are part of activity execution lifecycle, not authentication

### 2. **Activity-api DOES enforce connection limits**
- ✅ Right: activity-api queries api_keys and organizations tables (via identity-vessel or directly)
- **Reason**: Connection limits are enforced at connection time, which is activity-api's domain

### 3. **All vessels delegate authentication to identity-vessel**
- ✅ Every request includes: `Authorization: Bearer <token>`
- ✅ Vessels call `identity-vessel:8080/v1/auth/resolve` to validate
- ✅ Vessels never directly query users or api_keys tables
- **Reason**: Separation of concerns - authentication logic lives in one place

### 4. **Cost tracking lives in activity-api, not identity-vessel**
- ✅ Right: activity_executions table in activity-api
- ❌ Wrong: Cost tables in identity-vessel
- **Reason**: Costs are tied to activity executions, not authentication

### 5. **Dashboard is just a proxy + UI**
- ✅ Right: Dashboard has no business logic, just routing
- ❌ Wrong: Dashboard makes direct database queries
- **Reason**: UI should not have data access; backend vessels own their data

---

## Migration Plan

### Current State Issues

1. **identity-vessel has too many responsibilities**
   - Currently owns: users, organizations, api_keys, active_connections, activity_executions, cost_summaries
   - Should only own: users, organizations, api_keys

2. **Dashboard proxy configuration is wrong**
   - Currently proxies `/api/v2/*` to non-existent analysis-api
   - Should proxy to activity-api for activity/connection/cost data

### Migration Steps

1. **Move connection/activity/cost tables from identity-vessel to activity-api**
   ```sql
   -- In activity-api schema
   DEFINE TABLE active_connections ...
   DEFINE TABLE activity_executions ...
   DEFINE TABLE cost_summaries ...
   ```

2. **Update dashboard routing**
   ```typescript
   // Auth + Keys → identity-vessel
   if (pathname.startsWith('/api/auth/') || pathname.startsWith('/api/keys/')) {
     proxy to: identity-vessel
   }

   // Activity + Connections + Costs → activity-api
   if (pathname.startsWith('/api/v2/')) {
     proxy to: activity-api
   }
   ```

3. **Implement authentication middleware in activity-api**
   - Delegate to identity-vessel for validation
   - Cache validation results in Redis (5 min TTL)

4. **Implement connection management endpoints in activity-api**
   - `POST /v2/connections/establish`
   - `POST /v2/connections/heartbeat`
   - `POST /v2/connections/disconnect`
   - `GET /v2/connections`

5. **Implement activity tracking endpoints in activity-api** (if not already there)
   - `POST /v2/activities/start`
   - `POST /v2/activities/complete`

6. **Implement cost reporting endpoints in activity-api**
   - `GET /v2/costs/org/:id`
   - `GET /v2/costs/org/:id/projects`
   - `GET /v2/costs/org/:id/goals`

7. **Update MiniBob to report to activity-api**
   - Connection lifecycle
   - Activity start/complete

---

## Summary

**Identity-vessel**: Authentication & authorization only
**Activity-api**: Activity execution, connections, costs
**Concept-db**: Concept storage and lifecycle
**Dashboard**: UI proxy only
**MiniBob**: Activity executor client

**Golden Rule**: Vessels own their data. Other vessels call them via HTTP/MCP, never direct database access.
