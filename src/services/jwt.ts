/**
 * JWT Service - Single source of truth for JWT operations
 *
 * Provides:
 * - JWT token generation with configurable claims
 * - JWT token verification
 *
 * All other vessels should delegate to identity-vessel for JWT operations.
 */

import { sign, verify } from 'hono/jwt';
import type { JWTPayload } from 'hono/utils/jwt/types';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
const JWT_ISSUER = process.env.JWT_ISSUER || 'https://identity.metabob.com';

/**
 * Standard JWT claims for Metabob tokens
 * Extends JWTPayload for compatibility with hono/jwt sign()
 */
export interface MetabobJWTClaims extends JWTPayload {
  // Standard JWT claims (inherited from JWTPayload: iss, sub, iat, exp, etc.)
  iss: string;       // Issuer (identity.metabob.com)
  sub: string;       // Subject (user_id)
  iat: number;       // Issued at
  exp: number;       // Expiration

  // Metabob-specific claims
  org_id: string;    // Organization ID
  user_id: string;   // User ID (same as sub for clarity)
  role: string;      // User role (admin, member, viewer, owner)
  project_ids: string[]; // Accessible project IDs
  account_id?: string;   // Optional: caller's default account (record-reference-as-string, e.g. "accounts:metabob")
}

/**
 * Options for generating a JWT token
 *
 * `account_id` is optional and emitted alongside `org_id` during the
 * accounts/organizations migration window. Login/signup populate it from
 * account_members; legacy callers omit it (downstream tenant helpers fall
 * back to deriving from org_id).
 */
export interface GenerateTokenOptions {
  user_id: string;
  org_id: string;
  role: 'admin' | 'member' | 'viewer' | 'owner';
  project_ids?: string[];
  account_id?: string;
  expires_in_seconds?: number; // Default: 900 (15 minutes)
}

/**
 * Result of token generation
 */
export interface GenerateTokenResult {
  token: string;
  expires_at: string;
  issued_at: string;
}

/**
 * Result of token verification
 */
export interface VerifyTokenResult {
  valid: boolean;
  user_id?: string;
  org_id?: string;
  role?: string;
  project_ids?: string[];
  account_id?: string;
  exp?: number;
  iat?: number;
  error?: string;
}

/**
 * Generate a JWT token for a user
 *
 * @param options - Token generation options
 * @returns Token string and metadata
 */
export async function generateToken(options: GenerateTokenOptions): Promise<GenerateTokenResult> {
  const {
    user_id,
    org_id,
    role,
    project_ids = [],
    account_id,
    expires_in_seconds = 900, // 15 minutes default
  } = options;

  const now = Math.floor(Date.now() / 1000);
  const exp = now + expires_in_seconds;

  const payload: MetabobJWTClaims = {
    iss: JWT_ISSUER,
    sub: user_id,
    iat: now,
    exp,
    org_id,
    user_id,
    role,
    project_ids,
  };
  if (account_id) {
    payload.account_id = account_id;
  }

  const token = await sign(payload, JWT_SECRET, 'HS256');

  return {
    token,
    expires_at: new Date(exp * 1000).toISOString(),
    issued_at: new Date(now * 1000).toISOString(),
  };
}

/**
 * Verify a JWT token and extract claims
 *
 * @param token - JWT token string
 * @returns Verification result with claims if valid
 */
export async function verifyToken(token: string): Promise<VerifyTokenResult> {
  try {
    const payload = await verify(token, JWT_SECRET, 'HS256') as JWTPayload & Partial<MetabobJWTClaims>;

    // Check if token is expired (verify() should handle this, but be explicit)
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      return {
        valid: false,
        error: 'Token has expired',
      };
    }

    return {
      valid: true,
      user_id: payload.user_id || payload.sub as string,
      org_id: payload.org_id,
      role: payload.role,
      project_ids: payload.project_ids || [],
      account_id: payload.account_id,
      exp: payload.exp,
      iat: payload.iat,
    };
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'Token verification failed',
    };
  }
}

/**
 * Get the current JWT secret (for debugging/health checks only)
 * Returns masked version
 */
export function getSecretInfo(): { masked: string; length: number } {
  return {
    masked: JWT_SECRET.substring(0, 4) + '****' + JWT_SECRET.substring(JWT_SECRET.length - 4),
    length: JWT_SECRET.length,
  };
}
