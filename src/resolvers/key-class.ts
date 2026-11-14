/**
 * apiKeyClass resolver: each key's class, by masked id, for readers that attribute a write
 * made under a key principal (development-vessel's landing judge reads it through discovery).
 *
 * Served on identity's resolve door (POST /v1/auth/resolve, pointer.type 'apiKeyClass'),
 * advertised to discovery like identity's other shapes. The answer is
 *   { success: true, data: { keys: [{ key_id_mask12, row_mask8, owner_kind, owner_node, is_admin }] } }
 * and nothing else per key: never the key, its hash, its full id, its name or its scopes.
 *   - row_mask8: the first 8 characters of the row's record id, the row keyAnswer names for the key it answered,
 *     so a listed class and an answered class can be seen to come from the same row (or not).
 *   - key_id_mask12: the first 12 characters of the key's key_id (a key_id is 'key_' plus 16
 *     characters, so this is a prefix, never the whole id). A reader matches a principal's key
 *     id by prefix. A row with no key_id string, or one shorter than 13 characters (whose mask
 *     would be the whole id), is not listed: unlisted reads as unattributable, never as system.
 *   - owner_kind: 'system' | 'operator' | 'peer' | 'unclassified'. 'peer' is stamped only when
 *     the issuer declares it at issue with the joining node's name; no derivation produces it.
 *   - owner_node: the node name (SUBSTRATE_NAME) for a system key, which this identity issued
 *     to this node's services, and null when that name is unset; for a peer key, the node name
 *     declared at issue (null if the row holds none); null for every other key.
 *   - is_admin: the key's stored scopes include the literal 'admin' scope.
 *
 * Authorization: a service ApiKey, checked the way authorizeAdmin checks one (validateKey,
 * then the revocation list) without the admin-scope requirement. A Bearer token (a user
 * session, an on-behalf-of token) is refused. The read runs on identity's own connection,
 * like GET /v1/keys, which bypasses record PERMISSIONS, so the org filter is in this code:
 * a caller reads only its own org's keys.
 *
 * THE CLASS (the provenance claim): deriveOwnerKind (services/owner-kind.ts) is the one rule.
 * It stamps a key at issue (issue-key.ts), backfills existing rows at unit start
 * (db/migrations.ts), and answers for a row the backfill has not stamped. Every key identity holds is minted through
 * /v1/keys/issue or /v1/keys/bootstrap-admin by an admin credential for the org's own user,
 * so neither user_id nor the caller's credential kind tells a service key from a person's;
 * the name the issuer gave it is the only field that carries its issuance.
 */

import { validateKey } from '../services/validation';
import { isKeyRevoked } from '../db/redis';
import { storedOrDerived, type OwnerKind } from '../services/owner-kind';
import { recordIdOf } from '../services/answer-log';

export { deriveOwnerKind, ownerKindAtIssue, OWNER_KINDS, SYSTEM_KEY_NAMES, ADMIN_CREDENTIAL_NAMES, type OwnerKind } from '../services/owner-kind';

export const API_KEY_CLASS_SHAPE = 'apiKeyClass';

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

export interface KeyClassEntry {
  key_id_mask12: string;
  /** The first 8 characters of the row's record id: the same mask keyAnswer holds for the row validation read, so a
   *  reader can see that a listed class and an answered class come from the same row. */
  row_mask8: string;
  /** For a key a person made (person-key.ts): the first 12 characters of the key it was made under. Absent otherwise. */
  minted_from_mask12?: string;
  owner_kind: OwnerKind;
  owner_node: string | null;
  is_admin: boolean;
}

export type KeyClassFailureCode =
  | 'MISSING_AUTH_HEADER'
  | 'INVALID_AUTH_SCHEME'
  | 'INVALID_API_KEY'
  | 'REVOKED_API_KEY'
  | 'FORBIDDEN'
  | 'INVALID_INPUT'
  | 'READ_FAILED';

export type KeyClassResult =
  | { ok: true; keys: KeyClassEntry[] }
  | { ok: false; status: number; code: KeyClassFailureCode; message: string };

const fail = (status: number, code: KeyClassFailureCode, message: string): KeyClassResult => ({ ok: false, status, code, message });

/** The node name a system key belongs to: SUBSTRATE_NAME (bootstrap identity), or null. */
export function nodeName(): string | null {
  const n = (process.env.SUBSTRATE_NAME ?? '').trim();
  return n.length > 0 ? n : null;
}

/** The node a peer key was declared for at issue, or null when the row holds none. */
function peerNode(v: unknown): string | null {
  return typeof v === 'string' && v.length > 0 ? v : null;
}

/** One served entry from a stored row, or null when the row cannot be listed. Exported for tests. */
export function entryFromRow(row: Record<string, unknown>, node: string | null): KeyClassEntry | null {
  const id = row.key_id;
  if (typeof id !== 'string' || id.length <= 12) return null;
  const owner_kind = storedOrDerived(row.owner_kind, row.name);
  const scopes = Array.isArray(row.scopes) ? row.scopes : [];
  return {
    key_id_mask12: id.slice(0, 12),
    row_mask8: recordIdOf(row).slice(0, 8).replace(/[^A-Za-z0-9_:-]/g, '?') || '-',
    owner_kind,
    owner_node: owner_kind === 'system' ? node : owner_kind === 'peer' ? peerNode(row.owner_node) : null,
    is_admin: scopes.includes('admin'),
    ...(typeof row.minted_from === 'string' && row.minted_from !== '' ? { minted_from_mask12: row.minted_from.slice(0, 12).replace(/[^A-Za-z0-9_:-]/g, '?') } : {}),
  };
}

export type ServiceCaller = { ok: true; orgId: string } | { ok: false; status: number; code: KeyClassFailureCode; message: string };

/**
 * The org of a service ApiKey caller, for a read of the org's own key facts (apiKeyClass, keyAnswer): a valid,
 * unrevoked ApiKey that names an org. A Bearer token (a user session, an on-behalf-of token) is refused.
 */
export async function serviceCallerOrg(authHeader: string | undefined, shape: string): Promise<ServiceCaller> {
  const no = (status: number, code: KeyClassFailureCode, message: string): ServiceCaller => ({ ok: false, status, code, message });
  if (!authHeader) return no(401, 'MISSING_AUTH_HEADER', 'Missing Authorization header');
  if (authHeader.startsWith('Bearer ')) {
    return no(403, 'FORBIDDEN', `${shape} is read with a service ApiKey, not a session token`);
  }
  if (!authHeader.startsWith('ApiKey ')) {
    return no(401, 'INVALID_AUTH_SCHEME', 'Authorization must start with "ApiKey "');
  }
  const validation = await validateKey(authHeader.slice('ApiKey '.length));
  if (!validation.valid) return no(401, 'INVALID_API_KEY', 'Invalid API key');
  if (validation.keyId && (await isKeyRevoked(validation.keyId))) {
    return no(401, 'REVOKED_API_KEY', 'API key has been revoked');
  }
  if (!validation.orgId) return no(403, 'FORBIDDEN', 'The API key names no org');
  return { ok: true, orgId: validation.orgId };
}

/** Resolve apiKeyClass for the caller presenting `authHeader`. */
export async function readKeyClass(authHeader: string | undefined): Promise<KeyClassResult> {
  const caller = await serviceCallerOrg(authHeader, API_KEY_CLASS_SHAPE);
  if (!caller.ok) return caller;

  let rows: unknown;
  try {
    const query = await getQueryFn();
    // Never key_hash: the read selects only what the class is derived from.
    rows = await query('SELECT id, key_id, name, scopes, owner_kind, owner_node, minted_from FROM api_key WHERE org_id = $org_id;', { org_id: caller.orgId });
  } catch {
    return fail(500, 'READ_FAILED', 'Could not read the key class map');
  }
  const node = nodeName();
  const keys = (Array.isArray(rows) ? rows : [])
    .filter((r): r is Record<string, unknown> => !!r && typeof r === 'object')
    .map((r) => entryFromRow(r, node))
    .filter((e): e is KeyClassEntry => e !== null);
  const count = (k: OwnerKind) => keys.filter((e) => e.owner_kind === k).length;
  // Counts only: no key id, mask or name.
  console.log(`[apiKeyClass] served ${keys.length} key(s): system=${count('system')} operator=${count('operator')} peer=${count('peer')} unclassified=${count('unclassified')}`);
  return { ok: true, keys };
}
