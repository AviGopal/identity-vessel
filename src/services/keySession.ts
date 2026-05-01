/**
 * Key session tracking — records each JWT mint attributable to an api_key.
 *
 * The dashboard uses these rows to show, per key, session-creation count and
 * estimated active time (sum of expires_at - issued_at). "Estimated" because
 * we record JWT lifetime at mint, not actual usage.
 *
 * Writes are fire-and-forget — a failure to record must never block auth
 * resolution. Reads happen via /v1/keys/:keyId/sessions.
 */

export type KeySessionSource = 'resolve_nested' | 'resolve_flat' | 'generate';

export interface KeySessionRow {
  key_id: string;
  org_id: string;
  user_id?: string;
  issued_at: string;
  expires_at: string;
  source: KeySessionSource;
}

export interface KeySessionAggregate {
  key_id: string;
  count: number;
  total_estimated_seconds: number;
  first_seen?: string;
  last_seen?: string;
}

/**
 * Record a session row. Best-effort: any error is swallowed and logged.
 */
export async function recordKeySession(row: KeySessionRow): Promise<void> {
  try {
    const { query } = await import('../db/surrealdb');
    await query(
      `CREATE key_session SET
        key_id = $key_id,
        org_id = $org_id,
        user_id = $user_id,
        issued_at = <datetime> $issued_at,
        expires_at = <datetime> $expires_at,
        source = $source;`,
      {
        key_id: row.key_id,
        org_id: row.org_id,
        user_id: row.user_id ?? null,
        issued_at: row.issued_at,
        expires_at: row.expires_at,
        source: row.source,
      },
    );
  } catch (err) {
    console.warn('[keySession] record failed', {
      key_id: row.key_id,
      err: err instanceof Error ? err.message : String(err),
    });
  }
}

/**
 * List recent session rows for a key, plus an aggregate.
 *
 * `since` and `limit` are advisory — the caller should also paginate at the
 * UI layer for very-active keys.
 */
export async function listKeySessions(
  keyId: string,
  opts: { since?: string; limit?: number } = {},
): Promise<{ rows: KeySessionRow[]; aggregate: KeySessionAggregate }> {
  const { query } = await import('../db/surrealdb');
  const limit = Math.min(Math.max(opts.limit ?? 100, 1), 1000);

  const whereSince = opts.since ? 'AND issued_at >= <datetime> $since' : '';

  // Fetch rows, newest first.
  const rowResult = await query<any[]>(
    `SELECT key_id, org_id, user_id, issued_at, expires_at, source
     FROM key_session
     WHERE key_id = $key_id ${whereSince}
     ORDER BY issued_at DESC
     LIMIT ${limit};`,
    { key_id: keyId, since: opts.since },
  );

  const rows: KeySessionRow[] = (Array.isArray(rowResult) ? rowResult : []).map((r: any) => ({
    key_id: String(r.key_id),
    org_id: String(r.org_id),
    user_id: r.user_id ? String(r.user_id) : undefined,
    issued_at: typeof r.issued_at === 'string' ? r.issued_at : new Date(r.issued_at).toISOString(),
    expires_at: typeof r.expires_at === 'string' ? r.expires_at : new Date(r.expires_at).toISOString(),
    source: r.source as KeySessionSource,
  }));

  // Aggregate over the *full* history for this key (not just the page).
  // math::min/max don't accept datetimes, so we work in unix seconds and
  // re-hydrate ISO strings in JS.
  const aggResult = await query<any[]>(
    `SELECT
       count() AS count,
       math::sum(time::unix(expires_at) - time::unix(issued_at)) AS total_estimated_seconds,
       math::min(time::unix(issued_at)) AS first_seen_unix,
       math::max(time::unix(issued_at)) AS last_seen_unix
     FROM key_session
     WHERE key_id = $key_id ${whereSince}
     GROUP ALL;`,
    { key_id: keyId, since: opts.since },
  );

  const aggRow = (Array.isArray(aggResult) ? aggResult[0] : undefined) ?? {};
  const firstSeenUnix = Number(aggRow.first_seen_unix ?? 0);
  const lastSeenUnix = Number(aggRow.last_seen_unix ?? 0);
  const aggregate: KeySessionAggregate = {
    key_id: keyId,
    count: Number(aggRow.count ?? 0),
    total_estimated_seconds: Number(aggRow.total_estimated_seconds ?? 0),
    first_seen: firstSeenUnix > 0 ? new Date(firstSeenUnix * 1000).toISOString() : undefined,
    last_seen: lastSeenUnix > 0 ? new Date(lastSeenUnix * 1000).toISOString() : undefined,
  };

  return { rows, aggregate };
}
