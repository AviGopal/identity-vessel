/**
 * apiKey_write resolver — admin-only scope ADD on an existing key, with no rotation.
 *
 * Why it exists: the daemon tool gate admits its state-changing shapes only from
 * node-self, admin or tools-exec. A node seeded before goal-host's key was minted
 * with tools-exec keeps a [read, write] key, and nothing could change that short of
 * re-minting it: /v1/keys/issue and /v1/keys/generate set scopes only on a NEW key,
 * and PUT /v1/keys/:keyId only renames. A re-mint changes key_id and secret and
 * every consumer holding the old value. This writes the existing row instead.
 *
 * The write is a shaped impulse on identity's resolve door (POST /v1/auth/resolve,
 * pointer.type 'apiKey_write'), not a REST route, so it is advertised to discovery
 * like identity's other shape.
 *
 * It runs on the SAME connection identity issues and renames keys on: db/surrealdb.ts
 * query(), the root-signed-in session (mintApiKey's CREATE, PUT /v1/keys/:keyId's
 * UPDATE). Root bypasses record PERMISSIONS, and the api_key table carries none that
 * could guard this live, so EVERY guard below is in this code, and each is tested with
 * a database that would permit the write:
 *   - Admin only: authorizeAdmin (ApiKey with scope admin, or JWT role admin/owner).
 *   - Same org: the row's org_id must be the admin's own org (FORBIDDEN otherwise), and
 *     the UPDATE repeats it in its WHERE clause.
 *   - Allowlist: only GRANTABLE_SCOPES can be added, so this can never grant admin. It is
 *     a frozen constant in this file: only an identity commit can widen it.
 *   - Add only: the pointer carries add_scopes; any field that would set or remove
 *     scopes is refused, and the SQL unions — it never assigns a smaller set.
 *   - No rotation: the UPDATE sets `scopes` and nothing else; key_id, key_hash, prefix
 *     and every other field are untouched, so the key's value keeps working. It returns
 *     only key_id and scopes, so no key material comes back.
 *   - Never narrows: a row with no stored scopes validates as the default [read, write],
 *     which is written out along with the new scope.
 *   - Idempotent: a key that already holds every requested scope is not written.
 *   - Audit: one log line naming key_id and the scopes added. Never a key value.
 */

import { authorizeAdmin } from './issue-key';

export const API_KEY_WRITE_SHAPE = 'apiKey_write';

// What validation answers for a key whose row stores no scopes (validation.ts, /v1/keys/validate).
const DEFAULT_SCOPES: readonly string[] = Object.freeze(['read', 'write']);

/** The only scopes this write may add. admin is deliberately absent. */
export const GRANTABLE_SCOPES: readonly string[] = Object.freeze(['tools-exec']);

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

export type GrantFailureCode =
  | 'INVALID_INPUT'
  | 'REMOVAL_REFUSED'
  | 'SCOPE_NOT_GRANTABLE'
  | 'MISSING_AUTH_HEADER'
  | 'INVALID_AUTH_SCHEME'
  | 'INVALID_API_KEY'
  | 'REVOKED_API_KEY'
  | 'INVALID_JWT'
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'PERSIST_FAILED';

export interface GrantSuccess {
  ok: true;
  key_id: string;
  scopes: string[];
  added: string[];
  changed: boolean;
}

export interface GrantFailure {
  ok: false;
  status: number;
  code: GrantFailureCode;
  message: string;
}

export type GrantResult = GrantSuccess | GrantFailure;

function fail(status: number, code: GrantFailureCode, message: string): GrantFailure {
  return { ok: false, status, code, message };
}

const POINTER_FIELDS = new Set(['type', 'key_id', 'add_scopes']);
// Any of these would set or shrink the scope set; this write only ever adds.
const REMOVAL_FIELDS = ['remove_scopes', 'scopes', 'set_scopes', 'replace_scopes'];

function rows(result: unknown): any[] {
  return Array.isArray(result) ? result : ((result as any)?.result ?? []);
}

/** Add allowlisted scopes to an existing key. Admin-only; never rotates. */
export async function grantKeyScopes(pointer: unknown, authHeader: string | undefined): Promise<GrantResult> {
  const authz = await authorizeAdmin(authHeader);
  if ('status' in authz) return authz;
  if (!authz.org_id) return fail(403, 'FORBIDDEN', 'The admin credential names no org');

  if (!pointer || typeof pointer !== 'object') return fail(400, 'INVALID_INPUT', 'pointer must be an object');
  const p = pointer as Record<string, unknown>;
  if (REMOVAL_FIELDS.some((f) => f in p)) {
    return fail(400, 'REMOVAL_REFUSED', 'apiKey_write only adds scopes (add_scopes); it never sets or removes them');
  }
  const extra = Object.keys(p).filter((k) => !POINTER_FIELDS.has(k));
  if (extra.length > 0) return fail(400, 'INVALID_INPUT', `unsupported pointer fields: ${extra.join(', ')}`);
  if (typeof p.key_id !== 'string' || p.key_id.length === 0) {
    return fail(400, 'INVALID_INPUT', 'key_id must be a non-empty string');
  }
  if (!Array.isArray(p.add_scopes) || p.add_scopes.length === 0 || p.add_scopes.some((s) => typeof s !== 'string')) {
    return fail(400, 'INVALID_INPUT', 'add_scopes must be a non-empty array of strings');
  }
  const keyId = p.key_id;
  const add = [...new Set(p.add_scopes as string[])];
  const refused = add.filter((s) => !GRANTABLE_SCOPES.includes(s));
  if (refused.length > 0) {
    return fail(403, 'SCOPE_NOT_GRANTABLE', `not grantable: ${refused.join(', ')} (grantable: ${GRANTABLE_SCOPES.join(', ')})`);
  }

  let query: QueryFn;
  let row: any;
  try {
    query = await getQueryFn();
    row = rows(await query(`SELECT key_id, org_id, scopes FROM api_key WHERE key_id = $key_id LIMIT 1;`, { key_id: keyId }))[0];
  } catch (err) {
    return fail(500, 'PERSIST_FAILED', err instanceof Error ? err.message : 'Failed to read api_key row');
  }
  if (!row) return fail(404, 'NOT_FOUND', 'Key not found');
  if (row.org_id !== authz.org_id) return fail(403, 'FORBIDDEN', 'Key not in caller org');

  // A row with no stored scopes validates as the default [read, write] (lookupKeyScopes
  // returns null for an empty set, and validation falls back). Writing only the new scope
  // would leave exactly [tools-exec] and silently drop read and write, so the default is
  // written out explicitly along with it.
  const stored: string[] = Array.isArray(row.scopes) ? row.scopes : [];
  const current = stored.length > 0 ? stored : [...DEFAULT_SCOPES];
  const missing = add.filter((s) => !current.includes(s));
  if (missing.length === 0) {
    return { ok: true, key_id: keyId, scopes: [...current], added: [], changed: false };
  }
  const toWrite = [...current.filter((s) => !stored.includes(s)), ...missing];

  let updated: any;
  try {
    updated = rows(await query(
      `UPDATE api_key SET scopes = array::union(scopes ?? [], $add) WHERE key_id = $key_id AND org_id = $org_id RETURN key_id, scopes;`,
      { add: toWrite, key_id: keyId, org_id: authz.org_id },
    ))[0];
  } catch (err) {
    return fail(500, 'PERSIST_FAILED', err instanceof Error ? err.message : 'Failed to update api_key row');
  }
  if (!updated) return fail(500, 'PERSIST_FAILED', 'The api_key row was not updated');

  console.log('[ScopeGrant]', { key_id: keyId, added: missing });
  return {
    ok: true,
    key_id: keyId,
    scopes: Array.isArray(updated.scopes) ? updated.scopes : [...current, ...missing],
    added: missing,
    changed: true,
  };
}
