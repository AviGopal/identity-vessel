/**
 * Type definitions for identity vessel
 */

// API Key Components
export interface ApiKeyComponents {
  prefix: 'mb_live' | 'mb_test';
  orgId: string;
  userId: string;
  keyId: string;
  signature: string;
}

// API Key Metadata (stored in database)
export interface ApiKeyMetadata {
  id: string;
  org_id: string;
  user_id: string;
  key_prefix: string;
  name?: string;
  scopes: string[];
  created_at: string;
  expires_at?: string;
  last_used_at?: string;
  is_active: boolean;
  usage_count: number;
}

// Validation Result
export interface ValidationResult {
  valid: boolean;
  orgId?: string;
  userId?: string;
  keyId?: string;
  scopes?: string[];
  error?: string;
}

// Authentication Context
export interface AuthContext {
  orgId: string;
  userId: string;
  keyId?: string;
  type: 'api_key' | 'session';
  scopes: string[];
}

// Key Generation Options
export interface KeyGenerationOptions {
  name?: string;
  expiresInDays?: number;
  scopes?: string[];
}

// Key Generation Result
export interface KeyGenerationResult {
  key: string;
  keyId: string;
  prefix: string;
  expiresAt?: string;
}

// Authentication Impulse (for resolver pattern)
export interface AuthenticationImpulse {
  type: 'authentication';
  pointer: {
    type: 'apiKey' | 'session';
    apiKey?: string;
    token?: string;
  };
  budget?: number;
  priority?: 'high' | 'medium' | 'low';
}

// Authentication Result (for resolver pattern)
export interface AuthenticationResult {
  authenticated: boolean;
  orgId?: string;
  userId?: string;
  keyId?: string;
  type?: 'api_key' | 'session';
  scopes?: string[];
  reason?: string;
}

// Cost Tracking Types

// Activity Cost (per-execution cost record)
export interface ActivityCost {
  execution_id: string;
  org_id: string;
  user_id: string;
  api_key_id: string;
  project_id?: string;
  goal_description?: string;
  activity_template_id: string;
  instance_id: string;
  cost_usd: number;
  llm_tokens_used: number;
  llm_cost_usd: number;
  duration_ms: number;
  status: 'completed' | 'failed';
  started_at: string;
  completed_at: string;
}

// Cost Summary (aggregated costs)
export interface CostSummary {
  org_id: string;
  period_start: string;
  period_end: string;
  granularity: 'hour' | 'day' | 'week' | 'month';
  project_id?: string;
  goal_pattern?: string;
  total_executions: number;
  successful_executions: number;
  failed_executions: number;
  total_cost_usd: number;
  total_llm_tokens: number;
  total_llm_cost_usd: number;
  updated_at: string;
}

// Cost Record Request
export interface CostRecordRequest {
  execution_id: string;
  api_key_id: string;
  project_id?: string;
  goal_description?: string;
  activity_template_id: string;
  instance_id: string;
  cost_usd: number;
  llm_tokens_used: number;
  llm_cost_usd: number;
  duration_ms: number;
  status: 'completed' | 'failed';
  started_at: string;
  completed_at: string;
}

// Cost Query Filters
export interface CostQueryFilters {
  start_date?: string;
  end_date?: string;
  project_id?: string;
  goal_pattern?: string;
  granularity?: 'hour' | 'day' | 'week' | 'month';
}

// MiniBob Authentication Result
export interface MiniBobAuthResult {
  token: string;
  org_id: string;
  project_id?: string;
}
