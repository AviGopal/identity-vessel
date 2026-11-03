/**
 * The class of an API key (api_key.owner_kind): the one rule that stamps a key at issue
 * (resolvers/issue-key.ts), backfills existing rows at unit start (db/migrations.ts), and
 * answers apiKeyClass for a row with no stamp (resolvers/key-class.ts).
 *
 * Every key identity holds is minted through /v1/keys/issue or /v1/keys/bootstrap-admin by an
 * admin credential for the org's own user, so neither user_id nor the caller's credential
 * kind tells a service key from a person's; the name the issuer gave it is the only stored
 * field that carries its issuance. No imports: the unit-start schema step loads this module.
 */

export type OwnerKind = 'system' | 'operator' | 'peer' | 'unclassified';
export const OWNER_KINDS: readonly OwnerKind[] = Object.freeze(['system', 'operator', 'peer', 'unclassified'] as OwnerKind[]);

/**
 * Names the identity seeder (scripts/substrate/seed-identity.ts) gives the keys it issues to
 * vessel services, every name it has used: the fleet key and the per-vessel keys.
 */
export const SYSTEM_KEY_NAMES: readonly string[] = Object.freeze([
  'substrate-default',
  'local-tools-vessel',
  'goal-host-vessel',
  'goal-host-corpus-runner',
  'concept-db',
]);

/**
 * Names of the keyspace's admin credential: 'substrate-admin' (the seeder's, and the default
 * name of /v1/keys/bootstrap-admin), 'substrate-admin-backfill' (the seeder's recovery mint)
 * and 'substrate-admin-bootstrap' (substrate-key's recovery mint). Deliberately 'unclassified',
 * not 'operator': the credential is held by the operator tools and also used by the seeder, so
 * its writes are not traceable to either from the row. Listed so the choice is explicit and
 * pinned; no rule maps a name to 'operator'.
 */
export const ADMIN_CREDENTIAL_NAMES: readonly string[] = Object.freeze([
  'substrate-admin',
  'substrate-admin-backfill',
  'substrate-admin-bootstrap',
]);

/**
 * A key's class from the name it was issued under, exact and case-sensitive:
 *   SYSTEM_KEY_NAMES -> 'system'
 *   anything else, ADMIN_CREDENTIAL_NAMES and an absent or empty name included -> 'unclassified'
 * 'operator' is never derived from a name: it is stamped only when the issuer declares it.
 * A free-form name (substrate-key issue/join, a dashboard key) is untraceable: it may name a
 * peer node, a spoke, a person or a tool, so it is never guessed.
 */
export function deriveOwnerKind(name: unknown): OwnerKind {
  if (typeof name !== 'string' || name.length === 0) return 'unclassified';
  if (SYSTEM_KEY_NAMES.includes(name)) return 'system';
  return 'unclassified';
}

/**
 * The class stamped on a key at issue. An issuer may declare 'operator' (a key for a person
 * or an operator session), which wins over the name; it may not declare any other class, so
 * a declaration can only make a key's writes read as an operator's, never as the system's.
 * Returns null for a declaration that is not 'operator' (the caller refuses the request).
 */
export function ownerKindAtIssue(name: unknown, declared: unknown): OwnerKind | null {
  if (declared === undefined || declared === null) return deriveOwnerKind(name);
  return declared === 'operator' ? 'operator' : null;
}

/** A stored owner_kind when it is one of OWNER_KINDS, else the derivation from the name. */
export function storedOrDerived(stored: unknown, name: unknown): OwnerKind {
  return typeof stored === 'string' && (OWNER_KINDS as readonly string[]).includes(stored)
    ? (stored as OwnerKind)
    : deriveOwnerKind(name);
}

/** The statement the backfill stamps one row with. Exported for tests. */
export const BACKFILL_SELECT = 'SELECT id, name FROM api_key WHERE owner_kind = NONE;';
export const BACKFILL_UPDATE = 'UPDATE $id SET owner_kind = $owner_kind WHERE owner_kind = NONE;';

export interface BackfillReport { stamped: Record<OwnerKind, number>; failed: number }

/**
 * Stamp every row that has no owner_kind with deriveOwnerKind(name), one row at a time.
 * Idempotent (only unstamped rows, and the UPDATE repeats the condition). A row whose UPDATE
 * fails (a legacy row the SCHEMAFULL table refuses) is counted and left unstamped, which
 * readKeyClass answers by the same derivation: a failure here never fails the unit start.
 */
export async function backfillOwnerKind(
  run: (sql: string, params?: Record<string, unknown>) => Promise<unknown[]>,
): Promise<BackfillReport> {
  const report: BackfillReport = { stamped: { system: 0, operator: 0, peer: 0, unclassified: 0 }, failed: 0 };
  const [rows] = await run(BACKFILL_SELECT);
  for (const r of Array.isArray(rows) ? rows : []) {
    if (!r || typeof r !== 'object' || !('id' in r)) continue;
    const owner_kind = deriveOwnerKind((r as Record<string, unknown>).name);
    try {
      await run(BACKFILL_UPDATE, { id: (r as Record<string, unknown>).id, owner_kind });
      report.stamped[owner_kind] += 1;
    } catch {
      report.failed += 1;
    }
  }
  return report;
}
