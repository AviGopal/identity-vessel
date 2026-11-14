/**
 * ONE LINE PER KEY ANSWER, SAID WHEN IT CHANGES. A consumer stamps a row by the class identity answers for a key, and
 * nothing said which branch answered, which row it found or how. So a key the admin listing shows as a person's could be
 * stamped unmarked with no way to tell, from any log, whether another row, another branch or another identity answered.
 *
 * The line names: the branch (hmac: a key this identity's secret signs; legacy: an old-format key found by its stored
 * prefix; delegated: a key its issuer validated), the key id's first 12 characters, how the row was found (key_id,
 * key_prefix, record_id, none, ambiguous, error; bad_id when the id the key carries is not shaped like a key id, as one cut
 * short where it held a '-' would be; issuer for a delegated key), the first 8 characters of the row's record id, the stored owner_kind
 * (its value when it is a class, "invalid" when it is something else, "none" when absent) and the class answered.
 * Never a key, never a key_prefix value (on an old-format row it holds the key), never a hash.
 *
 * Said once per key while its answer stays the same, and again whenever it changes: a key validated on every call
 * would otherwise fill the journal. The map holds one entry per key that reached a row or an issuer, so it is bounded
 * by the keys that exist.
 */
import { OWNER_KINDS } from './owner-kind';

export type AnswerBranch = 'hmac' | 'legacy' | 'delegated';
export type FoundBy = 'key_id' | 'key_prefix' | 'record_id' | 'none' | 'ambiguous' | 'bad_id' | 'error' | 'issuer';

const said = new Map<string, string>();

/** Test-only: forget what was said. */
export function __resetAnswerLogForTests(): void {
  said.clear();
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

export function logKeyAnswer(a: {
  branch: AnswerBranch;
  keyId: string | null;
  foundBy: FoundBy;
  row?: Record<string, unknown>;
  answered: string | undefined;
}): void {
  const line =
    `branch=${a.branch} key=${head(a.keyId, 12)} found_by=${a.foundBy} row=${head(recordIdOf(a.row), 8)}` +
    ` owner_kind=${a.row ? storedOf(a.row.owner_kind) : '-'} answered=${a.answered ?? 'none'}`;
  const k = `${a.branch} ${a.keyId ?? '-'}`;
  if (said.get(k) === line) return;
  said.set(k, line);
  console.log(`[KeyAnswer] ${line}`);
}

/** The class an on-behalf-of token carries, said once per caller and audience while it stays the same. */
export function logOboMint(a: { scheme: 'api_key' | 'session'; keyId: string | undefined; ownerKind: string | undefined; node: string; shape: string }): void {
  const audience = `${head(a.node, 16)}/${head(a.shape, 40)}`;
  const line = `caller=${a.scheme} key=${head(a.keyId, 12)} carries=${head(a.ownerKind, 16) === '-' ? 'none' : head(a.ownerKind, 16)} audience=${audience}`;
  // Keyed by what is printed, so a caller's long node or shape strings cannot grow the map past what a line can say.
  const k = `obo ${a.scheme} ${a.keyId ?? '-'} ${audience}`;
  if (said.get(k) === line) return;
  said.set(k, line);
  console.log(`[OboMint] ${line}`);
}
