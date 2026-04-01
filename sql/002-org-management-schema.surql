-- =============================================================================
-- Organization Management: Complete Schema
-- Connection tracking, API key quotas, cost breakdown
-- =============================================================================

-- =============================================================================
-- Extend organizations table with connection limits
-- =============================================================================

DEFINE FIELD IF NOT EXISTS max_active_connections ON organizations TYPE option<int>
  DEFAULT 10
  COMMENT "Total simultaneous connections allowed for this organization";

DEFINE FIELD IF NOT EXISTS current_active_connections ON organizations TYPE int
  DEFAULT 0
  COMMENT "Current number of active connections (computed field)";

DEFINE FIELD IF NOT EXISTS billing_tier ON organizations TYPE option<string>
  DEFAULT "starter"
  COMMENT "Billing tier: starter, pro, enterprise";

-- =============================================================================
-- API Keys table with connection slot tracking
-- =============================================================================

DEFINE TABLE IF NOT EXISTS api_keys SCHEMAFULL;

DEFINE FIELD IF NOT EXISTS key_id ON api_keys TYPE string
  ASSERT $value != NONE
  COMMENT "Unique key identifier (embedded in HMAC key)";

DEFINE FIELD IF NOT EXISTS prefix ON api_keys TYPE string
  DEFAULT "mb_live_"
  COMMENT "Key prefix for display (mb_live_, mb_test_)";

DEFINE FIELD IF NOT EXISTS org_id ON api_keys TYPE record<organizations>
  ASSERT $value != NONE
  COMMENT "Organization this key belongs to";

DEFINE FIELD IF NOT EXISTS user_id ON api_keys TYPE record<users>
  ASSERT $value != NONE
  COMMENT "User/member who created this key";

DEFINE FIELD IF NOT EXISTS name ON api_keys TYPE option<string>
  COMMENT "User-provided key name (e.g., 'CI/CD Pipeline')";

DEFINE FIELD IF NOT EXISTS scopes ON api_keys TYPE array<string>
  DEFAULT ["read", "write"]
  COMMENT "API permissions for this key";

DEFINE FIELD IF NOT EXISTS max_connections ON api_keys TYPE int
  DEFAULT 1
  COMMENT "Maximum simultaneous connections for this key";

DEFINE FIELD IF NOT EXISTS current_connections ON api_keys TYPE int
  DEFAULT 0
  COMMENT "Current number of active connections";

DEFINE FIELD IF NOT EXISTS tier ON api_keys TYPE string
  DEFAULT "starter"
  COMMENT "Key tier: starter (1 conn), pro (5 conn), enterprise (custom)";

DEFINE FIELD IF NOT EXISTS status ON api_keys TYPE string
  DEFAULT "active"
  COMMENT "Key status: active, revoked, expired";

DEFINE FIELD IF NOT EXISTS revoked ON api_keys TYPE bool
  DEFAULT false;

DEFINE FIELD IF NOT EXISTS revoked_at ON api_keys TYPE option<datetime>
  COMMENT "When the key was revoked";

DEFINE FIELD IF NOT EXISTS revoked_reason ON api_keys TYPE option<string>
  COMMENT "Why the key was revoked";

DEFINE FIELD IF NOT EXISTS created_at ON api_keys TYPE datetime
  VALUE $value OR time::now();

DEFINE FIELD IF NOT EXISTS last_used_at ON api_keys TYPE option<datetime>
  COMMENT "Last time this key was used to authenticate";

DEFINE FIELD IF NOT EXISTS usage_count ON api_keys TYPE int
  DEFAULT 0
  COMMENT "Total number of API requests made with this key";

-- LLM budget tracking per key
DEFINE FIELD IF NOT EXISTS llm_budget ON api_keys TYPE option<object>
  COMMENT "Token budget: {tokens_per_month: int, tokens_used: int, reset_at: datetime}";

-- Unique constraint on key_id
DEFINE INDEX IF NOT EXISTS idx_api_keys_key_id
  ON api_keys FIELDS key_id UNIQUE;

-- Index for active keys by org
DEFINE INDEX IF NOT EXISTS idx_api_keys_org_active
  ON api_keys FIELDS org_id, status;

-- Index for user keys
DEFINE INDEX IF NOT EXISTS idx_api_keys_user
  ON api_keys FIELDS user_id;

-- =============================================================================
-- Active Connections table (tracks which instances are using which keys)
-- =============================================================================

DEFINE TABLE IF NOT EXISTS active_connections SCHEMAFULL;

DEFINE FIELD IF NOT EXISTS api_key_id ON active_connections TYPE record<api_keys>
  ASSERT $value != NONE
  COMMENT "API key being used";

DEFINE FIELD IF NOT EXISTS instance_id ON active_connections TYPE string
  ASSERT $value != NONE
  COMMENT "MiniBob instance ID or client identifier";

DEFINE FIELD IF NOT EXISTS instance_type ON active_connections TYPE string
  DEFAULT "minibob"
  COMMENT "Type: minibob, cli, ide, automation";

DEFINE FIELD IF NOT EXISTS org_id ON active_connections TYPE record<organizations>
  ASSERT $value != NONE
  COMMENT "Organization (denormalized for fast queries)";

DEFINE FIELD IF NOT EXISTS user_id ON active_connections TYPE record<users>
  ASSERT $value != NONE
  COMMENT "User (denormalized for fast queries)";

DEFINE FIELD IF NOT EXISTS connected_at ON active_connections TYPE datetime
  VALUE $value OR time::now()
  COMMENT "When this connection was established";

DEFINE FIELD IF NOT EXISTS last_heartbeat_at ON active_connections TYPE datetime
  VALUE $value OR time::now()
  COMMENT "Last time this connection sent a heartbeat";

DEFINE FIELD IF NOT EXISTS disconnected_at ON active_connections TYPE option<datetime>
  COMMENT "When this connection ended (null = still active)";

DEFINE FIELD IF NOT EXISTS client_metadata ON active_connections TYPE option<object>
  COMMENT "Client info: {version, platform, ip, user_agent}";

-- Unique constraint: one entry per api_key + instance
DEFINE INDEX IF NOT EXISTS idx_active_connections_key_instance
  ON active_connections FIELDS api_key_id, instance_id UNIQUE;

-- Index for finding active connections by org
DEFINE INDEX IF NOT EXISTS idx_active_connections_org_active
  ON active_connections FIELDS org_id, disconnected_at;

-- Index for finding connections by api key
DEFINE INDEX IF NOT EXISTS idx_active_connections_api_key
  ON active_connections FIELDS api_key_id, disconnected_at;

-- =============================================================================
-- Activity Executions table (tracks what activities ran with which keys)
-- =============================================================================

DEFINE TABLE IF NOT EXISTS activity_executions SCHEMAFULL;

DEFINE FIELD IF NOT EXISTS execution_id ON activity_executions TYPE string
  ASSERT $value != NONE
  COMMENT "Unique execution ID from activity-api";

DEFINE FIELD IF NOT EXISTS api_key_id ON activity_executions TYPE record<api_keys>
  ASSERT $value != NONE
  COMMENT "API key used for this execution";

DEFINE FIELD IF NOT EXISTS org_id ON activity_executions TYPE record<organizations>
  ASSERT $value != NONE;

DEFINE FIELD IF NOT EXISTS user_id ON activity_executions TYPE record<users>
  ASSERT $value != NONE;

DEFINE FIELD IF NOT EXISTS instance_id ON activity_executions TYPE string
  ASSERT $value != NONE
  COMMENT "Which instance ran this activity";

DEFINE FIELD IF NOT EXISTS activity_template_id ON activity_executions TYPE string
  ASSERT $value != NONE
  COMMENT "Activity template used";

DEFINE FIELD IF NOT EXISTS project_id ON activity_executions TYPE option<string>
  COMMENT "Project this activity was associated with";

DEFINE FIELD IF NOT EXISTS goal_description ON activity_executions TYPE option<string>
  COMMENT "Goal or intent for this execution";

DEFINE FIELD IF NOT EXISTS started_at ON activity_executions TYPE datetime
  VALUE $value OR time::now();

DEFINE FIELD IF NOT EXISTS completed_at ON activity_executions TYPE option<datetime>;

DEFINE FIELD IF NOT EXISTS status ON activity_executions TYPE string
  DEFAULT "running"
  COMMENT "Status: running, completed, failed";

DEFINE FIELD IF NOT EXISTS duration_ms ON activity_executions TYPE option<int>
  COMMENT "Execution duration in milliseconds";

-- Cost tracking
DEFINE FIELD IF NOT EXISTS cost_usd ON activity_executions TYPE option<float>
  COMMENT "Total cost in USD for this execution";

DEFINE FIELD IF NOT EXISTS llm_tokens_used ON activity_executions TYPE option<int>
  COMMENT "Total LLM tokens consumed";

DEFINE FIELD IF NOT EXISTS llm_cost_usd ON activity_executions TYPE option<float>
  COMMENT "LLM cost in USD";

DEFINE FIELD IF NOT EXISTS tool_calls_count ON activity_executions TYPE option<int>
  COMMENT "Number of tool calls made";

-- Index for execution lookups
DEFINE INDEX IF NOT EXISTS idx_activity_executions_id
  ON activity_executions FIELDS execution_id UNIQUE;

-- Index for cost queries by org + project
DEFINE INDEX IF NOT EXISTS idx_activity_executions_org_project
  ON activity_executions FIELDS org_id, project_id, started_at;

-- Index for cost queries by org + goal
DEFINE INDEX IF NOT EXISTS idx_activity_executions_org_goal
  ON activity_executions FIELDS org_id, goal_description, started_at;

-- Index for api key usage
DEFINE INDEX IF NOT EXISTS idx_activity_executions_api_key
  ON activity_executions FIELDS api_key_id, started_at;

-- =============================================================================
-- Cost Summary table (aggregated costs per org/project/time period)
-- =============================================================================

DEFINE TABLE IF NOT EXISTS cost_summaries SCHEMAFULL;

DEFINE FIELD IF NOT EXISTS org_id ON cost_summaries TYPE record<organizations>
  ASSERT $value != NONE;

DEFINE FIELD IF NOT EXISTS period_start ON cost_summaries TYPE datetime
  ASSERT $value != NONE
  COMMENT "Start of aggregation period (day/week/month)";

DEFINE FIELD IF NOT EXISTS period_end ON cost_summaries TYPE datetime
  ASSERT $value != NONE;

DEFINE FIELD IF NOT EXISTS granularity ON cost_summaries TYPE string
  DEFAULT "day"
  COMMENT "Aggregation level: hour, day, week, month";

DEFINE FIELD IF NOT EXISTS project_id ON cost_summaries TYPE option<string>
  COMMENT "If set, summary is for specific project";

DEFINE FIELD IF NOT EXISTS goal_pattern ON cost_summaries TYPE option<string>
  COMMENT "If set, summary is for activities matching this goal pattern";

DEFINE FIELD IF NOT EXISTS total_executions ON cost_summaries TYPE int
  DEFAULT 0;

DEFINE FIELD IF NOT EXISTS successful_executions ON cost_summaries TYPE int
  DEFAULT 0;

DEFINE FIELD IF NOT EXISTS failed_executions ON cost_summaries TYPE int
  DEFAULT 0;

DEFINE FIELD IF NOT EXISTS total_cost_usd ON cost_summaries TYPE float
  DEFAULT 0.0;

DEFINE FIELD IF NOT EXISTS total_llm_tokens ON cost_summaries TYPE int
  DEFAULT 0;

DEFINE FIELD IF NOT EXISTS total_llm_cost_usd ON cost_summaries TYPE float
  DEFAULT 0.0;

DEFINE FIELD IF NOT EXISTS updated_at ON cost_summaries TYPE datetime
  VALUE time::now()
  COMMENT "Last time this summary was updated";

-- Unique index for period summaries
DEFINE INDEX IF NOT EXISTS idx_cost_summaries_period
  ON cost_summaries FIELDS org_id, granularity, period_start, project_id, goal_pattern UNIQUE;
