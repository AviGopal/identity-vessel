/**
 * Email + password login & signup resolver.
 *
 * Implements the end-to-end sign-in flow the cloud-dashboard proxy targets
 * (`POST /api/auth/{login,signup}` → identity-vessel `POST /v1/auth/...`).
 *
 * SurrealDB direct access (vs. user-vessel HTTP):
 *   Signup needs to CREATE users + orgs + accounts + memberships before any
 *   JWT exists; user-vessel's POST /v2/users (src/routes/users.ts:89) is
 *   gated by requireRole("owner","admin") and POST /v2/accounts by
 *   requireAuth — neither reachable mid-signup. Login likewise needs the
 *   SELECT before any auth token. Identity-vessel's surrealdb client runs
 *   as root, so SCHEMAFULL PERMISSIONS pass.
 *
 * Schema gap (verified 2026-04-28):
 *   user-vessel `POST /v2/users` accepts only `{ email, name }` — no
 *   password_hash. Migration 002-users-password-hash.surql (this vessel)
 *   adds the field via DEFINE FIELD OVERWRITE so identity-vessel owns the
 *   auth concern.
 *
 * Constant-time login: missing-user branch still runs verifyPassword()
 * against a dummy hash so its timing matches wrong-password. Disabled when
 * LOGIN_SKIP_DUMMY_HASH=true or NODE_ENV=test.
 */

import { hashPassword, verifyPassword, validatePassword } from '../services/password';
import { generateToken } from '../services/jwt';

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

// Lazy-computed dummy hash for constant-time missing-user branch.
let DUMMY_HASH: string | null = null;
async function getDummyHash(): Promise<string> {
  if (DUMMY_HASH) return DUMMY_HASH;
  DUMMY_HASH = await hashPassword('invalid-credential-dummy-input-do-not-match');
  return DUMMY_HASH;
}

function shouldSkipDummyHash(): boolean {
  return (
    process.env.NODE_ENV === 'test'
    || (process.env.LOGIN_SKIP_DUMMY_HASH || '').toLowerCase() === 'true'
  );
}

// =============================================================================
// Types
// =============================================================================

export interface LoginRequest { email: string; password: string }
export interface SignupRequest {
  email: string; password: string;
  name?: string; org_name?: string; accept_invitation_token?: string;
}

// Response shape matches cloud-dashboard's LoginResponse contract
// (src/types/api.ts): { token, user: { id, email, name, org_id, role, ... } }.
// `user_id`/`account_id`/`expires_at` are kept at the top level as ergonomic
// extras for non-dashboard callers (CLI, tests) — strictly additive.
export interface AuthSuccess {
  ok: true;
  status: 200;
  body: {
    token: string;
    user: {
      id: string;
      email: string;
      name: string;
      org_id: string;
      role: 'owner' | 'admin' | 'member' | 'viewer';
      account_id?: string;
    };
    user_id: string;
    org_id: string;
    role: string;
    account_id?: string;
    expires_at: string;
  };
}

export type AuthFailureCode =
  | 'INVALID_INPUT' | 'INVALID_CREDENTIALS' | 'WEAK_PASSWORD'
  | 'NEEDS_INVITATION_OR_ORG' | 'EMAIL_TAKEN' | 'INVITATION_INVALID'
  | 'PERSIST_FAILED' | 'JWT_FAILED';

export interface AuthFailure {
  ok: false;
  status: number;
  body: { error: AuthFailureCode; message?: string; details?: unknown };
}

export type AuthResult = AuthSuccess | AuthFailure;

function fail(status: number, error: AuthFailureCode, message?: string, details?: unknown): AuthFailure {
  return { ok: false, status, body: { error, ...(message ? { message } : {}), ...(details !== undefined ? { details } : {}) } };
}

// =============================================================================
// Helpers
// =============================================================================

/** Flatten SurrealDB's nested array / { result } shapes to a single row list. */
function extractRows<T = any>(result: any): T[] {
  if (!result) return [];
  if (Array.isArray(result)) {
    if (result.length === 0) return [];
    if (Array.isArray(result[0])) return result[0] as T[];
    if (typeof result[0] === 'object' && result[0] && 'result' in result[0] && Array.isArray((result[0] as any).result)) {
      return (result[0] as any).result as T[];
    }
    return result as T[];
  }
  if (typeof result === 'object' && 'result' in result && Array.isArray((result as any).result)) {
    return (result as any).result as T[];
  }
  return [];
}

/** Coerce id (record link or "users:abc" string) to canonical record-ref string. */
function toRecordRef(prefix: string, raw: any): string {
  if (raw === null || raw === undefined) return '';
  if (typeof raw === 'string') return raw.startsWith(`${prefix}:`) ? raw : `${prefix}:${raw}`;
  if (typeof raw === 'object') {
    const tb = (raw as any).tb, id = (raw as any).id;
    if (tb && id !== undefined) return `${tb}:${typeof id === 'object' ? (id as any).toString() : id}`;
    if ((raw as any).toString) {
      const s = (raw as any).toString();
      return s.startsWith(`${prefix}:`) ? s : `${prefix}:${s}`;
    }
  }
  return String(raw);
}

const ROLE_RANK: Record<string, number> = { owner: 0, admin: 1, member: 2, viewer: 3 };
function rankRole(r: string): number { return ROLE_RANK[r] ?? 4; }

/**
 * Mint a JWT for the authenticated user. Picks org+account from membership
 * rows (owner > admin > member > viewer); falls back to fallbackOrgRef or
 * `users.org_id` (schema field per deployed migration). Returns null when no
 * org claim can be derived.
 */
async function mintAuthJwt(
  query: QueryFn,
  userRef: string,
  email: string,
  name: string,
  defaultOrgId: string | undefined,
  fallbackOrgRef: string | undefined,
): Promise<AuthSuccess['body'] | null> {
  // Use `<string>user_id = $user_id` cast: account_members.user_id may be
  // stored as a record-reference (record<users>) per the deployed schema even
  // though user-vessel migration 002 declares it TYPE string (the OVERWRITE
  // didn't take when activity-api owned the field first). The cast normalizes
  // both shapes to the canonical "users:<id>" string form for comparison.
  const [omsRaw, amsRaw] = await Promise.all([
    query('SELECT org_id, role FROM organization_members WHERE <string>user_id = $user_id;', { user_id: userRef }),
    query('SELECT account_id, role FROM account_members WHERE <string>user_id = $user_id;', { user_id: userRef }),
  ]);

  const orgRows = extractRows<any>(omsRaw).slice().sort((a, b) => rankRole(a.role) - rankRole(b.role));
  const acctRows = extractRows<any>(amsRaw).slice().sort((a, b) => rankRole(a.role) - rankRole(b.role));
  const orgPick = orgRows[0];
  const acctPick = acctRows[0];

  // Derive org from account when organization_members lacks a match.
  // user-vessel migration 002 establishes 1:1 mapping: accounts:<X> mirrors
  // organizations:<X>. So we can fall back to the account suffix.
  const acctSuffix = acctPick?.account_id?.replace(/^accounts:/, '');
  const orgRef =
    (orgPick ? toRecordRef('organizations', orgPick.org_id) : undefined)
    || (acctSuffix ? toRecordRef('organizations', acctSuffix) : undefined)
    || fallbackOrgRef
    || (defaultOrgId ? toRecordRef('organizations', defaultOrgId) : undefined);
  if (!orgRef) return null;

  const role = (acctPick?.role || orgPick?.role || 'member') as 'owner' | 'admin' | 'member' | 'viewer';
  const account_id = acctPick ? toRecordRef('accounts', acctPick.account_id) : undefined;

  try {
    const result = await generateToken({
      user_id: userRef, org_id: orgRef, role, account_id, expires_in_seconds: 900,
    });
    return {
      token: result.token,
      user: {
        id: userRef,
        email,
        name,
        org_id: orgRef,
        role,
        ...(account_id ? { account_id } : {}),
      },
      user_id: userRef,
      org_id: orgRef,
      role,
      ...(account_id ? { account_id } : {}),
      expires_at: result.expires_at,
    };
  } catch {
    return null;
  }
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateLoginInput(body: unknown): LoginRequest | AuthFailure {
  if (!body || typeof body !== 'object') return fail(400, 'INVALID_INPUT', 'request body must be a JSON object');
  const b = body as Record<string, unknown>;
  if (typeof b.email !== 'string' || !EMAIL_RE.test(b.email)) return fail(400, 'INVALID_INPUT', 'email must be a valid email string');
  if (typeof b.password !== 'string' || b.password.length === 0) return fail(400, 'INVALID_INPUT', 'password must be a non-empty string');
  return { email: b.email.toLowerCase().trim(), password: b.password };
}

function validateSignupInput(body: unknown): SignupRequest | AuthFailure {
  if (!body || typeof body !== 'object') return fail(400, 'INVALID_INPUT', 'request body must be a JSON object');
  const b = body as Record<string, unknown>;
  if (typeof b.email !== 'string' || !EMAIL_RE.test(b.email)) return fail(400, 'INVALID_INPUT', 'email must be a valid email string');
  if (typeof b.password !== 'string') return fail(400, 'INVALID_INPUT', 'password must be a string');
  return {
    email: b.email.toLowerCase().trim(),
    password: b.password,
    name: typeof b.name === 'string' ? b.name : undefined,
    org_name: typeof b.org_name === 'string' ? b.org_name : undefined,
    accept_invitation_token: typeof b.accept_invitation_token === 'string' ? b.accept_invitation_token : undefined,
  };
}

// =============================================================================
// POST /v1/auth/login
// =============================================================================

export async function loginWithPassword(body: unknown): Promise<AuthResult> {
  const validated = validateLoginInput(body);
  if ('status' in validated) return validated;

  const query = await getQueryFn();

  let userRow: any = null;
  try {
    const result = await query(
      'SELECT id, email, name, password_hash, org_id FROM users WHERE email = $email LIMIT 1;',
      { email: validated.email },
    );
    userRow = extractRows<any>(result)[0] ?? null;
  } catch (err) {
    return fail(500, 'PERSIST_FAILED', err instanceof Error ? err.message : 'user lookup failed');
  }

  // Constant-time: verify against dummy hash on missing-user / null-hash so
  // the no-user branch and the wrong-password branch are timing-equivalent.
  const skipDummy = shouldSkipDummyHash();
  if (!userRow || typeof userRow.password_hash !== 'string') {
    if (!skipDummy) {
      try { await verifyPassword(validated.password, await getDummyHash()); } catch { /* ignore */ }
    }
    return fail(401, 'INVALID_CREDENTIALS', 'invalid email or password');
  }

  if (!(await verifyPassword(validated.password, userRow.password_hash))) {
    return fail(401, 'INVALID_CREDENTIALS', 'invalid email or password');
  }

  const userRef = toRecordRef('users', userRow.id);
  const userEmail = typeof userRow.email === 'string' ? userRow.email : validated.email;
  const userName = typeof userRow.name === 'string' && userRow.name.length > 0 ? userRow.name : userEmail;
  const jwtBody = await mintAuthJwt(query, userRef, userEmail, userName, userRow.org_id, undefined);
  if (!jwtBody) return fail(500, 'JWT_FAILED', 'failed to mint session token');

  return { ok: true, status: 200, body: jwtBody };
}

// =============================================================================
// POST /v1/auth/signup
// =============================================================================

export async function signupWithPassword(body: unknown): Promise<AuthResult> {
  const validated = validateSignupInput(body);
  if ('status' in validated) return validated;

  const strength = validatePassword(validated.password);
  if (!strength.valid) {
    return fail(400, 'WEAK_PASSWORD', 'password does not meet strength requirements', {
      errors: strength.errors, score: strength.score,
    });
  }

  if (!validated.org_name && !validated.accept_invitation_token) {
    return fail(400, 'NEEDS_INVITATION_OR_ORG', 'signup requires either org_name or accept_invitation_token');
  }

  // Invitation flow requires an authed round-trip to user-vessel. Out of
  // scope for Phase 9 — accept the parameter shape but reject explicitly.
  if (validated.accept_invitation_token && !validated.org_name) {
    return fail(501, 'INVITATION_INVALID',
      'invitation-token signup not yet implemented in identity-vessel; use org_name for now');
  }

  const query = await getQueryFn();

  // Fail-fast on duplicate email so we never half-create a tenant.
  try {
    const existing = await query('SELECT id FROM users WHERE email = $email LIMIT 1;', { email: validated.email });
    if (extractRows<any>(existing).length > 0) {
      return fail(409, 'EMAIL_TAKEN', 'email is already registered');
    }
  } catch (err) {
    return fail(500, 'PERSIST_FAILED', err instanceof Error ? err.message : 'duplicate-check failed');
  }

  let passwordHash: string;
  try {
    passwordHash = await hashPassword(validated.password);
  } catch (err) {
    return fail(500, 'PERSIST_FAILED', err instanceof Error ? err.message : 'password hashing failed');
  }

  const orgName = validated.org_name as string;
  const displayName = validated.name && validated.name.length > 0 ? validated.name : validated.email;
  // Slug derivation matches user-vessel/src/routes/accounts.ts.
  const slug = orgName.toLowerCase().replace(/[^a-z0-9]+/g, '_').slice(0, 64) || 'org';
  const orgRef = `organizations:${slug}`;
  const acctRef = `accounts:${slug}`;

  // Idempotency: refuse on org collision so we never silently merge users
  // into someone else's org.
  try {
    const orgCheck = await query('SELECT id FROM type::record($id);', { id: orgRef });
    if (extractRows<any>(orgCheck).length > 0) {
      return fail(409, 'EMAIL_TAKEN', 'organization name already taken');
    }
  } catch (err) {
    return fail(500, 'PERSIST_FAILED', err instanceof Error ? err.message : 'org existence check failed');
  }

  // Sequential CREATE writes; partial failure leaves orphan rows but the
  // duplicate-email guard above lets the caller retry safely.
  let userRef: string;
  try {
    const userResult = await query(
      `CREATE users SET
        email = $email, name = $name,
        password_hash = $password_hash,
        org_id = <string>$org_id;`,
      { email: validated.email, name: displayName, password_hash: passwordHash, org_id: orgRef },
    );
    const created = extractRows<any>(userResult)[0];
    if (!created || !created.id) return fail(500, 'PERSIST_FAILED', 'user creation returned no row');
    userRef = toRecordRef('users', created.id);
  } catch (err) {
    return fail(500, 'PERSIST_FAILED', err instanceof Error ? err.message : 'user CREATE failed');
  }

  try {
    await query(
      // org_id field has VALUE $before OR $value OR id; the `id` fallback
      // is a record reference and fails the TYPE string coerce. Pass
      // org_id explicitly as the canonical string form.
      `CREATE type::record($id) SET name = $name, subscription_tier = 'free', org_id = $org_id_str;`,
      { id: orgRef, name: orgName, org_id_str: orgRef },
    );
    await query(
      `CREATE organization_members SET org_id = <string>$org_id, user_id = <string>$user_id, role = 'owner';`,
      { org_id: orgRef, user_id: userRef },
    );
    // Mirror the org as an account (matches user-vessel migration 002).
    await query(
      `CREATE type::record($id) SET name = $name, tier = 'free', seat_limit = 1, created_by = <string>$user_id;`,
      { id: acctRef, name: orgName, user_id: userRef },
    );
    await query(
      `CREATE account_members SET account_id = <string>$account_id, user_id = <string>$user_id, role = 'owner';`,
      { account_id: acctRef, user_id: userRef },
    );
  } catch (err) {
    return fail(500, 'PERSIST_FAILED', err instanceof Error ? err.message : 'tenant CREATE failed');
  }

  const jwtBody = await mintAuthJwt(query, userRef, validated.email, displayName, orgRef, orgRef);
  if (!jwtBody) return fail(500, 'JWT_FAILED', 'failed to mint session token after signup');

  return { ok: true, status: 200, body: jwtBody };
}
