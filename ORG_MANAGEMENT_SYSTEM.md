# Organization Management System

Complete organization, member, and API key management with connection tracking and cost breakdown.

## Data Model Hierarchy

```
Organization
├── max_active_connections (total limit across all keys)
├── current_active_connections (computed)
├── billing_tier (starter/pro/enterprise)
└── Members (users)
    └── API Keys
        ├── max_connections (per-key limit)
        ├── current_connections (active slots)
        ├── llm_budget {tokens_per_month, tokens_used}
        └── Active Connections (0...n)
            └── Instance (MiniBob/CLI/IDE)
                └── Activity Executions
                    ├── cost_usd
                    ├── project_id
                    └── goal_description
```

## Tables

### 1. `organizations`
- **Purpose**: Top-level tenant boundary
- **Key fields**:
  - `max_active_connections` - Total simultaneous connections allowed
  - `current_active_connections` - Real-time count
  - `billing_tier` - starter/pro/enterprise

### 2. `users` (members)
- **Purpose**: Organization members who own API keys
- **Key fields**:
  - `org_id` - Organization membership
  - `email`, `name`, `password_hash`

### 3. `api_keys`
- **Purpose**: Authentication credentials with connection quotas
- **Key fields**:
  - `org_id`, `user_id` - Ownership
  - `max_connections` - How many simultaneous connections this key allows
  - `current_connections` - Active count
  - `tier` - starter (1), pro (5), enterprise (custom)
  - `status` - active/revoked/expired
  - `llm_budget` - Token limits and usage

**Tiers**:
- **Starter**: 1 connection, 1M tokens/month
- **Pro**: 5 connections, 10M tokens/month
- **Enterprise**: Custom limits

### 4. `active_connections`
- **Purpose**: Track which instances are using which API keys
- **Key fields**:
  - `api_key_id`, `instance_id` - Connection identity
  - `org_id`, `user_id` - Denormalized for fast queries
  - `instance_type` - minibob/cli/ide/automation
  - `connected_at`, `last_heartbeat_at` - Lifecycle
  - `disconnected_at` - NULL = still active
  - `client_metadata` - {version, platform, ip}

**Constraint**: Unique per (api_key_id, instance_id)

### 5. `activity_executions`
- **Purpose**: Track what activities ran and their costs
- **Key fields**:
  - `api_key_id`, `org_id`, `user_id`, `instance_id`
  - `activity_template_id`, `project_id`, `goal_description`
  - `status` - running/completed/failed
  - `duration_ms`
  - `cost_usd`, `llm_tokens_used`, `llm_cost_usd`
  - `tool_calls_count`

### 6. `cost_summaries`
- **Purpose**: Aggregated costs per org/project/goal over time
- **Key fields**:
  - `org_id`, `period_start`, `period_end`, `granularity` (hour/day/week/month)
  - `project_id` (optional) - For project-specific summaries
  - `goal_pattern` (optional) - For goal-specific summaries
  - `total_executions`, `successful_executions`, `failed_executions`
  - `total_cost_usd`, `total_llm_tokens`, `total_llm_cost_usd`

## Connection Flow

### 1. Client Connects
```typescript
POST /v1/connections/establish
{
  "api_key": "mb_live_...",
  "instance_id": "minibob-123",
  "instance_type": "minibob",
  "client_metadata": {
    "version": "1.0.0",
    "platform": "linux"
  }
}
```

**Validation**:
1. Verify API key is valid and not revoked
2. Check `api_key.current_connections < api_key.max_connections`
3. Check `org.current_active_connections < org.max_active_connections`
4. Create `active_connections` record
5. Increment `api_key.current_connections` and `org.current_active_connections`

**Response**:
```json
{
  "connection_id": "conn_abc123",
  "established_at": "2026-04-01T08:00:00Z",
  "heartbeat_interval_sec": 60,
  "quota_remaining": {
    "key_slots": 4,
    "org_slots": 95
  }
}
```

### 2. Client Sends Heartbeat
```typescript
POST /v1/connections/heartbeat
{
  "connection_id": "conn_abc123",
  "instance_id": "minibob-123"
}
```

Updates `last_heartbeat_at`. If no heartbeat for 5 minutes, connection is considered stale and cleaned up.

### 3. Client Disconnects
```typescript
POST /v1/connections/disconnect
{
  "connection_id": "conn_abc123"
}
```

**Cleanup**:
1. Set `disconnected_at = now()`
2. Decrement `api_key.current_connections` and `org.current_active_connections`

## Activity Tracking Flow

### 1. Activity Started
```typescript
POST /v1/activities/start
{
  "connection_id": "conn_abc123",
  "execution_id": "exec_xyz",
  "activity_template_id": "template_123",
  "project_id": "proj_456",
  "goal_description": "Fix authentication bug"
}
```

Creates `activity_executions` record with `status = "running"`.

### 2. Activity Completed
```typescript
POST /v1/activities/complete
{
  "execution_id": "exec_xyz",
  "status": "completed",  // or "failed"
  "duration_ms": 45000,
  "cost_usd": 0.15,
  "llm_tokens_used": 12500,
  "llm_cost_usd": 0.125,
  "tool_calls_count": 42
}
```

Updates `activity_executions` record. Triggers cost summary aggregation.

## Cost Breakdown Queries

### By Organization (All Time)
```sql
SELECT
  SUM(cost_usd) AS total_cost,
  SUM(llm_tokens_used) AS total_tokens,
  COUNT(*) AS total_executions
FROM activity_executions
WHERE org_id = $org_id;
```

### By Project (Last 30 Days)
```sql
SELECT
  project_id,
  SUM(cost_usd) AS project_cost,
  COUNT(*) AS executions
FROM activity_executions
WHERE org_id = $org_id
  AND project_id != NONE
  AND started_at > time::now() - 30d
GROUP BY project_id
ORDER BY project_cost DESC;
```

### By Goal Pattern (Last 7 Days)
```sql
SELECT
  goal_description,
  SUM(cost_usd) AS goal_cost,
  AVG(duration_ms) AS avg_duration_ms,
  COUNT(*) AS executions
FROM activity_executions
WHERE org_id = $org_id
  AND goal_description != NONE
  AND started_at > time::now() - 7d
GROUP BY goal_description
ORDER BY goal_cost DESC
LIMIT 10;
```

### Aggregated Daily Summaries
```sql
SELECT * FROM cost_summaries
WHERE org_id = $org_id
  AND granularity = "day"
  AND period_start > time::now() - 30d
ORDER BY period_start DESC;
```

## API Endpoints Needed

### Organization Management
- `GET /v1/orgs/:id` - Get org details + current connection usage
- `PATCH /v1/orgs/:id` - Update max_active_connections, billing_tier
- `GET /v1/orgs/:id/members` - List members
- `POST /v1/orgs/:id/members` - Add member
- `DELETE /v1/orgs/:id/members/:user_id` - Remove member

### API Key Management
- `GET /v1/keys` - List user's API keys
- `POST /v1/keys` - Generate new API key (returns secret once!)
- `PATCH /v1/keys/:id` - Update tier, max_connections
- `DELETE /v1/keys/:id` - Revoke key
- `GET /v1/keys/:id/connections` - List active connections for key
- `GET /v1/keys/:id/activity` - Recent activities for key

### Connection Management
- `POST /v1/connections/establish` - Establish connection
- `POST /v1/connections/heartbeat` - Send heartbeat
- `POST /v1/connections/disconnect` - Clean disconnect
- `GET /v1/connections` - List active connections (org-wide or per-key)
- `DELETE /v1/connections/:id` - Force disconnect (admin)

### Activity Tracking
- `POST /v1/activities/start` - Record activity start
- `POST /v1/activities/complete` - Record activity completion
- `GET /v1/activities` - List activities (filterable by org/project/goal/key)

### Cost Reporting
- `GET /v1/costs/org/:id` - Organization total costs
- `GET /v1/costs/org/:id/projects` - Cost breakdown by project
- `GET /v1/costs/org/:id/goals` - Cost breakdown by goal
- `GET /v1/costs/org/:id/timeline` - Daily/weekly/monthly cost timeline
- `GET /v1/costs/summaries` - Pre-aggregated cost summaries

## Connection Lifecycle Example

```
1. MiniBob starts up
   → POST /v1/connections/establish
   → Receives connection_id, quota info

2. Every 60 seconds
   → POST /v1/connections/heartbeat
   → Confirms connection still alive

3. MiniBob receives a goal
   → POST /v1/activities/start
   → Records execution start

4. Activity completes
   → POST /v1/activities/complete
   → Records cost, tokens, duration

5. MiniBob shuts down
   → POST /v1/connections/disconnect
   → Frees up connection slot
```

## Connection Slot Enforcement

### At API Key Level
```typescript
if (api_key.current_connections >= api_key.max_connections) {
  return {
    error: "API key connection limit reached",
    max: api_key.max_connections,
    current: api_key.current_connections,
    message: "Upgrade to Pro tier for 5 simultaneous connections"
  };
}
```

### At Organization Level
```typescript
if (org.current_active_connections >= org.max_active_connections) {
  return {
    error: "Organization connection limit reached",
    max: org.max_active_connections,
    current: org.current_active_connections,
    message: "Contact sales to increase your organization's connection limit"
  };
}
```

## Stale Connection Cleanup

Background job runs every 2 minutes:

```sql
-- Find stale connections (no heartbeat for 5+ minutes)
SELECT * FROM active_connections
WHERE disconnected_at = NONE
  AND last_heartbeat_at < time::now() - 5m;

-- Mark as disconnected
UPDATE active_connections
SET disconnected_at = time::now()
WHERE id IN $stale_connection_ids;

-- Decrement counters
FOR $conn IN $stale_connections {
  UPDATE $conn.api_key_id
  SET current_connections -= 1;

  UPDATE $conn.org_id
  SET current_active_connections -= 1;
}
```

## Cost Aggregation Job

Runs hourly to populate `cost_summaries`:

```sql
-- Daily summary for organization
INSERT INTO cost_summaries (
  org_id,
  period_start,
  period_end,
  granularity,
  total_executions,
  successful_executions,
  failed_executions,
  total_cost_usd,
  total_llm_tokens,
  total_llm_cost_usd
)
SELECT
  org_id,
  time::floor(started_at, 1d) AS period_start,
  time::floor(started_at, 1d) + 1d AS period_end,
  "day" AS granularity,
  COUNT(*) AS total_executions,
  COUNT(CASE WHEN status = "completed" THEN 1 END) AS successful_executions,
  COUNT(CASE WHEN status = "failed" THEN 1 END) AS failed_executions,
  SUM(cost_usd OR 0) AS total_cost_usd,
  SUM(llm_tokens_used OR 0) AS total_llm_tokens,
  SUM(llm_cost_usd OR 0) AS total_llm_cost_usd
FROM activity_executions
WHERE started_at >= time::floor(time::now() - 2d, 1d)
GROUP BY org_id, period_start;
```

## Next Steps

1. **Implement connection management endpoints** in identity-vessel
2. **Add activity tracking endpoints** (or delegate to activity-api)
3. **Create background jobs** for:
   - Stale connection cleanup
   - Cost aggregation
   - Budget enforcement (pause keys that exceed token limits)
4. **Build dashboard UI** for:
   - API key management with real-time connection counts
   - Active connections table (who's using what)
   - Cost breakdown charts (by project, by goal, over time)
5. **Integrate with MiniBob** to report activities and maintain heartbeat
