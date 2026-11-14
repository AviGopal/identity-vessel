/**
 * THE LAST ANSWER IDENTITY GAVE FOR EACH KEY, HELD TO BE READ (keyAnswer). A consumer stamps a row by the class identity
 * answers for a key. When a key the admin listing shows as a person's came back unclassified, nothing a reader could ask
 * said which branch answered, which row it found or how, so finding the cause took operators reading journals. This
 * holds each answer as a fact the keyAnswer shape serves (resolvers/key-answer.ts), to a service key of the same org.
 *
 * An answer holds: the branch (hmac: a key this identity's secret signs; legacy: an old-format key found by its stored
 * prefix; delegated: a key its issuer validated), the key id's first 12 characters, how the row was found (key_id,
 * key_prefix, record_id, none, ambiguous, error; bad_id when the id the key carries is not shaped like a key id, as one
 * cut short where it held a '-' would be; issuer for a delegated key), the first 8 characters of the row's record id, the
 * stored owner_kind (its value when it is a class, "invalid" when it is something else, "none" when absent), the class
 * answered, and when. An on-behalf-of mint holds the caller's scheme, key head, the class the token carries and its
 * audience. Never a key, never a key_prefix value (on an old-format row it holds the key), never a hash.
 *
 * Held in memory, since this identity started: a restart empties it, and the reader is told when that was, so an empty
 * answer reads as "nothing answered here since then", never as "no mismatch". An answer whose org is unknown (an
 * old-format key with no row) is not held: no reader could be shown it.
 *
 * BOUNDS. Key answers: one entry per key, replaced by its latest answer, so bounded by the keys that passed HMAC or
 * found a row. Mint answers are held apart, since a caller chooses a mint's audience and could add one entry per shape
 * string it names: at most MINT_ANSWERS_PER_KEY per caller key and MINT_ANSWERS_HELD in all, the oldest dropped first,
 * so mints can never push out the key answers a reader needs, and one key cannot fill the mint store. Both are memory
 * bounds, not behaviour a reader steers.
 *
 * ORG ISOLATION is this module's filter (heldAnswers), not database PERMISSIONS: the store is in memory. Each entry is
 * held under the org the answer was given for, and a reader is shown only its own org's.
 */
import { OWNER_KINDS } from './owner-kind';

export type AnswerBranch = 'hmac' | 'legacy' | 'delegated';
export type FoundBy = 'key_id' | 'key_prefix' | 'record_id' | 'none' | 'ambiguous' | 'bad_id' | 'error' | 'issuer';

export type HeldKeyAnswer = {
  kind: 'key';
  key_mask12: string;
  branch: AnswerBranch;
  found_by: FoundBy;
  row_mask8: string;
  stored: string;
  answered: string;
  at: string;
};
export type HeldOboMint = {
  kind: 'obo_mint';
  key_mask12: string;
  scheme: 'api_key' | 'session';
  carries: string;
  audience: string;
  at: string;
};
export type HeldAnswer = HeldKeyAnswer | HeldOboMint;

const STARTED_AT = new Date().toISOString();
/** When this identity started holding answers: everything held is since then. */
export function heldSince(): string {
  return STARTED_AT;
}

const keyAnswers = new Map<string, { org: string; answer: HeldAnswer }>();
const mintAnswers = new Map<string, { org: string; answer: HeldAnswer }>();
export const MINT_ANSWERS_HELD = 4096;
export const MINT_ANSWERS_PER_KEY = 16;

/** Test-only: forget what is held. */
export function __resetAnswerLogForTests(): void {
  keyAnswers.clear();
  mintAnswers.clear();
}

const head = (s: unknown, n: number): string => (typeof s === 'string' && s !== '' ? s.slice(0, n).replace(/[^A-Za-z0-9_:-]/g, '?') : '-');

/** The record id of a row without its table name, whatever form the driver gives it in. */
export function recordIdOf(row: Record<string, unknown> | undefined): string {
  if (!row || row.id === undefined || row.id === null) return '';
  return String(row.id).replace(/^api_key:/, '').replace(/^[⟨`]|[⟩`]$/g, '');
}

/** How findKeyRow's single row matched the id it was given: read from key_id and the record id, never from key_prefix. */
export function foundByOf(row: Record<string, unknown>, keyId: string): FoundBy {
  if (row.key_id === keyId) return 'key_id';
  if (recordIdOf(row) === keyId) return 'record_id';
  return 'key_prefix';
}

const storedOf = (stored: unknown): string =>
  stored === undefined || stored === null ? 'none' : typeof stored === 'string' && (OWNER_KINDS as readonly string[]).includes(stored) ? stored : 'invalid';

export function recordKeyAnswer(a: {
  branch: AnswerBranch;
  keyId: string | null;
  orgId: unknown;
  foundBy: FoundBy;
  row?: Record<string, unknown>;
  answered: string | undefined;
}): void {
  if (typeof a.orgId !== 'string' || a.orgId === '') return;
  const answer: HeldKeyAnswer = {
    kind: 'key',
    key_mask12: head(a.keyId, 12),
    branch: a.branch,
    found_by: a.foundBy,
    row_mask8: head(recordIdOf(a.row), 8),
    stored: a.row ? storedOf(a.row.owner_kind) : '-',
    answered: head(a.answered, 16) === '-' ? 'none' : head(a.answered, 16),
    at: new Date().toISOString(),
  };
  keyAnswers.set(`key ${a.branch} ${a.keyId ?? '-'}`, { org: a.orgId, answer });
}

export function recordOboMint(a: { scheme: 'api_key' | 'session'; keyId: string | undefined; orgId: unknown; ownerKind: string | undefined; node: string; shape: string }): void {
  if (typeof a.orgId !== 'string' || a.orgId === '') return;
  const audience = `${head(a.node, 16)}/${head(a.shape, 40)}`;
  const answer: HeldOboMint = {
    kind: 'obo_mint',
    key_mask12: head(a.keyId, 12),
    scheme: a.scheme,
    carries: head(a.ownerKind, 16) === '-' ? 'none' : head(a.ownerKind, 16),
    audience,
    at: new Date().toISOString(),
  };
  // Keyed by what is held; re-set at the end, so the oldest is the first in the map and the first dropped.
  const caller = `obo ${a.scheme} ${a.keyId ?? '-'} `;
  const k = caller + audience;
  mintAnswers.delete(k);
  mintAnswers.set(k, { org: a.orgId, answer });
  const own = [...mintAnswers.keys()].filter((x) => x.startsWith(caller));
  for (const x of own.slice(0, Math.max(0, own.length - MINT_ANSWERS_PER_KEY))) mintAnswers.delete(x);
  while (mintAnswers.size > MINT_ANSWERS_HELD) {
    const oldest = mintAnswers.keys().next().value as string;
    mintAnswers.delete(oldest);
  }
}

/** What is held for one org, optionally only for keys whose 12-character mask starts with `mask`, newest first. */
export function heldAnswers(org: string, mask?: string): HeldAnswer[] {
  return [...keyAnswers.values(), ...mintAnswers.values()]
    .filter((h) => h.org === org && (mask === undefined || h.answer.key_mask12.startsWith(mask)))
    .map((h) => h.answer)
    .sort((x, y) => (x.at < y.at ? 1 : x.at > y.at ? -1 : 0));
}
