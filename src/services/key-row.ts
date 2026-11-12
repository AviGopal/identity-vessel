/**
 * The one way an api_key row is found by a key's id, for every reader and writer that does: validation (lookupKeyRow)
 * and apiKey_write. Two finding the same key by different rules is how a key that authenticated could not be marked.
 *
 * Rows keep a key's id in one of three places, by the path that wrote them: key_id (issue-key.ts), key_prefix (the
 * user-vessel schema stores an HMAC key's id there), or the record id api_key:<id> (old-format rows with no key_id;
 * record::id, not type::record, which on the deployed SurrealDB is a cast). So all three are matched, with two guards:
 *   - only a value shaped like a key id is looked up. On an old-format row key_prefix holds the key itself, and on
 *     generated keys a shared label ('mb'); neither is ever a lookup value;
 *   - exactly one row must match. More than one is refused, never one picked: a key's class must belong to one row.
 */

export const KEY_ID_SHAPE = /^key_[A-Za-z0-9_-]{8,}$/;
export const KEY_ROW_BY_ID = 'key_id = $key_id OR key_prefix = $key_id OR record::id(id) = $key_id';

type QueryFn = (sql: string, params?: Record<string, any>) => Promise<any>;
export type KeyRowFound = { row: Record<string, any> } | { none: true } | { ambiguous: true } | { badId: true };

/** The rows a query answered: the wrapper gives a statement's result as an array, or as { result }. */
export const rowsOf = (result: unknown): any[] => (Array.isArray(result) ? result : ((result as any)?.result ?? []));

/** The single api_key row for a key id, selecting `fields` (never the key value or hash), or why there is none. */
export async function findKeyRow(query: QueryFn, keyId: unknown, fields: string): Promise<KeyRowFound> {
  if (typeof keyId !== 'string' || !KEY_ID_SHAPE.test(keyId)) return { badId: true };
  const rows = rowsOf(await query(`SELECT ${fields} FROM api_key WHERE ${KEY_ROW_BY_ID} LIMIT 2;`, { key_id: keyId }));
  if (!Array.isArray(rows) || rows.length === 0) return { none: true };
  if (rows.length > 1) return { ambiguous: true };
  return { row: rows[0] };
}
