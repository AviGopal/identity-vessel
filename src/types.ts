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
  keyId: string;
  type: 'api_key';
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
    type: 'apiKey';
    apiKey: string;
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
  scopes?: string[];
  reason?: string;
}
