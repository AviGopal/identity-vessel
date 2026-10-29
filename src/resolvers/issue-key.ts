/**
 * Issue API Key resolver — admin-only key minting.
 *
 * Mints a canonical HMAC-signed API key, persists the row in api_key, and
 * returns the full key (returned ONCE; only the SHA-256 hash is stored).
 *
 * Auth: caller presents either an ApiKey with "admin" scope (DB-backed via
 * lookupKeyScopes) or a Bearer JWT with role=admin/owner. Authorization
 * lives in this resolver (not middleware) so unit tests can exercise the full
 * flow without spinning up Hono.
 */

import { generateApiKey } from '../services/keyGeneration';
import { validateKey } from '../services/validation';
import { isKeyRevoked } from '../db/redis';
import { verify as verifyJwt } from 'hono/jwt';
import { safeJwtErrorMessage } from '../services/redact';
import { createHash } from 'crypto';

type QueryFn = (sql: string, params?: Record<string, any>) => Promise<any>;
let queryOverride: QueryFn | null = null;

/** Test-only: substitute the SurrealDB query function. Pass null to reset. */
export function setQueryFn(fn: QueryFn | null): void {
  queryOverride = fn;
}

async function getQueryFn(): Promise<QueryFn> {
  if (queryOverride) return queryOverride;
  const mod = await import('../db/surrealdb');
  return mod.query as QueryFn;
}

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';

export interface IssueKeyRequest {
  user_id: string;        // record reference, e.g. "users:abc123"
  org_id: string;         // record reference, e.g. "organizations:metabob"
  scopes?: string[];      // default ["read","write"]
  expires_in_days?: number;
  name?: string;
}

export interface IssueKeySuccess {
  ok: true;
  key: string;            // returned ONCE; never persisted
  key_id: string;         // HMAC-embedded keyId, also the api_key record id
  expires_at?: string;
}

export type FailureCode =
  | 'INVALID_INPUT'
  | 'MISSING_AUTH_HEADER'
  | 'INVALID_AUTH_SCHEME'
  | 'INVALID_API_KEY'
  | 'REVOKED_API_KEY'
  | 'INVALID_JWT'
  | 'FORBIDDEN'
  | 'PERSIST_FAILED';

export interface IssueKeyFailure {
  ok: false;
  status: number;
  code: FailureCode;
  message: string;
}

export type IssueKeyResult = IssueKeySuccess | IssueKeyFailure;

function fail(status: number, code: FailureCode, message: string): IssueKeyFailure {
  return { ok: false, status, code, message };
}

/**
 * The authenticated admin caller. `is_admin` is always true when ok: authorizeAdmin
 * admits only an ApiKey with scope admin or a Bearer with role admin/owner (the same
 * entitlement /v1/jwt/generate calls callerIsAdmin). It is carried explicitly so the
 * key-target binding below states its rule rather than inferring it from the call site.
 */
export interface AdminAuthz {
  ok: true;
  org_id?: string;
  user_id?: string;
  is_admin: true;
}

export async function authorizeAdmin(
  authHeader: string | undefined,
): Promise<AdminAuthz | IssueKeyFailure> {
  if (!authHeader) return fail(401, 'MISSING_AUTH_HEADER', 'Missing Authorization header');

  if (authHeader.startsWith('ApiKey ')) {
    const apiKey = authHeader.slice('ApiKey '.length);
    const validation = await validateKey(apiKey);
    if (!validation.valid) return fail(401, 'INVALID_API_KEY', validation.error || 'Invalid API key');
    if (validation.keyId && (await isKeyRevoked(validation.keyId))) {
      return fail(401, 'REVOKED_API_KEY', 'API key has been revoked');
    }
    if (!(validation.scopes || []).includes('admin')) {
      return fail(403, 'FORBIDDEN', 'API key does not have admin scope');
    }
    // The admin's own org and user, for a caller that scopes its write to them (grant-scope.ts).
    return { ok: true, org_id: validation.orgId, user_id: validation.userId, is_admin: true };
  }

  if (authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice('Bearer '.length);
    let payload: any;
    try {
      payload = await verifyJwt(token, JWT_SECRET, 'HS512');
    } catch (err) {
      // NEVER surface `err.message` here. This calls hono's `verify` DIRECTLY
      // rather than through services/jwt.ts's verifyToken(), so it does not
      // inherit the mapping added there — and hono interpolates the presented
      // token into its exception message, which this `message` returns
      // verbatim in the 401 body. See services/redact.ts.
      return fail(401, 'INVALID_JWT', safeJwtErrorMessage(err));
    }
    if (payload?.typ === 'obo') return fail(403, 'FORBIDDEN', 'An on-behalf-of token cannot authorize administration');
    const role = (payload?.role as string | undefined) ?? '';
    if (role !== 'admin' && role !== 'owner') return fail(403, 'FORBIDDEN', 'JWT role is not admin');
    return { ok: true, org_id: payload?.org_id, user_id: payload?.user_id ?? payload?.sub, is_admin: true };
  }

  return fail(401, 'INVALID_AUTH_SCHEME', 'Authorization must start with "ApiKey " or "Bearer "');
}

/**
 * Bind a key request's target (org_id, user_id) to the authenticated caller,
 * following the rule /v1/jwt/generate applies to the claims it mints, with the
 * same FORBIDDEN shape.
 *
 *   - A missing org_id defaults to the caller's org, and a missing user_id to the
 *     caller's user. Never to anything else.
 *   - org_id must equal the caller's org; otherwise 403.
 *   - user_id may differ from the caller's only when the target org is the caller's
 *     own AND the caller is admin (an ApiKey with scope admin, or a Bearer with role
 *     admin/owner): a same-org admin issuing for a member. Otherwise 403. Membership
 *     of that user is not checked here (identity holds no membership table); the
 *     minted key is bound to the caller's org either way, which is what tenant
 *     isolation (PERMISSIONS on $token.org_id) keys on.
 *
 * Shared by /v1/keys/issue (issueApiKey) and /v1/keys/generate (index.ts).
 * Returns the body with org_id/user_id resolved, or a 403 failure. A non-object
 * body is passed through untouched so each route's own input validation answers it.
 */
export function bindKeyTarget(
  body: unknown,
  authz: AdminAuthz,
): unknown {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return body;
  if (!authz.org_id) return fail(403, 'FORBIDDEN', 'The admin credential names no org');
  const b = body as Record<string, unknown>;
  const missing = (v: unknown) => v === undefined || v === null;

  const org_id = missing(b.org_id) ? authz.org_id : b.org_id;
  if (org_id !== authz.org_id) {
    return fail(403, 'FORBIDDEN', 'Key org_id must match the authenticated credential');
  }

  const user_id = missing(b.user_id) ? authz.user_id : b.user_id;
  if (user_id !== authz.user_id && !(org_id === authz.org_id && authz.is_admin === true)) {
    return fail(403, 'FORBIDDEN', 'Issuing a key for another user requires admin entitlement in the same org');
  }

  return { ...b, org_id, user_id };
}

/** True when bindKeyTarget refused the request. */
export function isIssueKeyFailure(v: unknown): v is IssueKeyFailure {
  return !!v && typeof v === 'object' && (v as any).ok === false && 'status' in (v as any);
}

function validateInput(body: unknown): IssueKeyRequest | IssueKeyFailure {
  if (!body || typeof body !== 'object') {
    return fail(400, 'INVALID_INPUT', 'Request body must be a JSON object');
  }
  const b = body as Record<string, unknown>;

  if (typeof b.user_id !== 'string' || b.user_id.length === 0) {
    return fail(400, 'INVALID_INPUT', 'user_id must be a non-empty string (record reference)');
  }
  if (typeof b.org_id !== 'string' || b.org_id.length === 0) {
    return fail(400, 'INVALID_INPUT', 'org_id must be a non-empty string (record reference)');
  }

  let scopes: string[] | undefined;
  if (b.scopes !== undefined) {
    if (!Array.isArray(b.scopes) || b.scopes.some((s) => typeof s !== 'string')) {
      return fail(400, 'INVALID_INPUT', 'scopes must be an array of strings');
    }
    scopes = b.scopes as string[];
  }

  let expires_in_days: number | undefined;
  if (b.expires_in_days !== undefined) {
    if (typeof b.expires_in_days !== 'number' || b.expires_in_days <= 0) {
      return fail(400, 'INVALID_INPUT', 'expires_in_days must be a positive number');
    }
    expires_in_days = b.expires_in_days;
  }

  return {
    user_id: b.user_id,
    org_id: b.org_id,
    scopes,
    expires_in_days,
    name: typeof b.name === 'string' ? b.name : undefined,
  };
}

/** Issue a new API key. Admin-only; the key's org (and, for a non-admin, user) is the caller's own. */
export async function issueApiKey(
  body: unknown,
  authHeader: string | undefined,
): Promise<IssueKeyResult> {
  const authz = await authorizeAdmin(authHeader);
  if ('status' in authz) return authz;

  const bound = bindKeyTarget(body, authz);
  if (isIssueKeyFailure(bound)) return bound;

  return mintApiKey(bound);
}

/**
 * Mint + persist a key, WITHOUT any authorization check.
 *
 * Split out of issueApiKey() so a caller that has established authority by some
 * other means can reuse the exact minting path rather than reimplementing it.
 * The only such caller is the loopback admin-bootstrap resolver, which proves
 * in-container root by presenting API_KEY_SECRET; see bootstrap-admin.ts for why
 * that path has to exist at all.
 *
 * Anything reachable from the network MUST go through issueApiKey() instead.
 * This function grants an arbitrary scope set, including 'admin', to any caller.
 */
export async function mintApiKey(body: unknown): Promise<IssueKeyResult> {
  const validated = validateInput(body);
  if ('status' in validated) return validated;

  const scopes = validated.scopes ?? ['read', 'write'];

  const generated = generateApiKey(validated.org_id, validated.user_id, {
    name: validated.name,
    scopes,
    expiresInDays: validated.expires_in_days,
  });

  const keyHash = createHash('sha256').update(generated.key).digest('hex');

  // SurrealDB 3.x renamed `type::thing` → `type::record`; we avoid the helper
  // entirely and use the auto-generated id, persisting the HMAC-embedded keyId
  // separately as `key_id` (indexed) so `lookupKeyScopes()` can find it.
  // The deployed `api_key` schema (per identity-vessel migration 001) types
  // `org_id` and `user_id` as TYPE string, so we pass them through verbatim.
  // The api_key.expires_at schema field is `none | datetime` — passing NULL
  // fails coercion. Omit the SET clause entirely when no expiration is set so
  // the field defaults to NONE.
  // Same pattern as expires_at above: when name is absent, omit the SET clause
  // entirely so the schema's `name TYPE option<string>` field defaults to NONE.
  // Passing JS `null` fails the option<string> coerce in SurrealDB 3.x.
  const sql = `CREATE api_key SET
        key_id = $key_id,
        key_hash = $key_hash,
        org_id = $org_id,
        user_id = $user_id,
        scopes = $scopes,
        prefix = $prefix,
        created_at = time::now(),
        is_active = true${
          validated.name ? ',\n        name = $name' : ''
        }${
          generated.expiresAt ? ',\n        expires_at = <datetime>$expires_at' : ''
        };`;
  const params: Record<string, unknown> = {
    key_id: generated.keyId,
    key_hash: keyHash,
    org_id: validated.org_id,
    user_id: validated.user_id,
    scopes,
    prefix: generated.key.split('-').slice(0, 2).join('-'),
  };
  if (validated.name) params.name = validated.name;
  if (generated.expiresAt) params.expires_at = generated.expiresAt;

  try {
    const query = await getQueryFn();
    await query(sql, params);
  } catch (err) {
    return fail(500, 'PERSIST_FAILED', err instanceof Error ? err.message : 'Failed to persist api_key row');
  }

  return {
    ok: true,
    key: generated.key,
    key_id: generated.keyId,
    expires_at: generated.expiresAt,
  };
}
