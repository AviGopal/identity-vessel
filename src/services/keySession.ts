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

// Amortized reap tuning. SurrealDB (RocksDB) has no native record TTL, so
// expired key_session rows accumulate unboundedly and have previously grown to
// millions, thrashing the host. Rather than a static timer (law 5 prefers no
// timers), we fold a *bounded* sweep of provably-expired rows into the
// fire-and-forget write path: roughly one in REAP_EVERY healthy writes triggers
// a reap of up to REAP_BATCH rows. Any backlog drains over successive auth calls.
const REAP_EVERY = 50;
const REAP_BATCH = 500;
let writeCounter = 0;
let reaping = false; // in-flight latch: skip redundant overlapping reaps

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

    // A successful CREATE proves the connection is healthy; ride it to amortize
    // an expired-row reap. Fully fire-and-forget so it never blocks or fails the
    // auth hot path.
    if (++writeCounter % REAP_EVERY === 0) {
      void reapExpiredKeySessions();
    }
  } catch (err) {
    console.warn('[keySession] record failed', {
      key_id: row.key_id,
      err: err instanceof Error ? err.message : String(err),
    });
  }
}

/**
 * Bounded reap of provably-expired key_session rows. Deletes ONLY rows whose
 * expires_at is already past — the sole auth-safe predicate. No auth decision
 * reads key_session (JWT validity is self-contained in the token; api-key
 * validation uses HMAC + Redis revocation), so removing expired rows cannot
 * affect any active session or in-flight auth. expires_at is schema-required
 * (ASSERT != NONE) so the comparison never mishandles nulls. Bounded two-step
 * (SELECT ids LIMIT N, then point-DELETE the array) rides idx_ks_expires and
 * keeps the transaction small — no full-table lock. Best-effort; errors swallowed.
 */
export async function reapExpiredKeySessions(limit: number = REAP_BATCH): Promise<void> {
  if (reaping) return;
  reaping = true;
  const n = Math.max(1, Math.floor(limit));
  try {
    const { query } = await import('../db/surrealdb');
    await query(
      `LET $ids = SELECT VALUE id FROM key_session
         WHERE expires_at < time::now()
         LIMIT ${n};
       DELETE $ids RETURN NONE;`,
    );
  } catch (err) {
    console.warn('[keySession] reap failed', {
      err: err instanceof Error ? err.message : String(err),
    });
  } finally {
    reaping = false;
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

  // Fetch rows, newest first.  WITH INDEX forces use of the composite index on
  // (key_id, issued_at) even for keys with zero matching rows, avoiding a full
  // 849K-row scan.
  const rowResult = await query<any[]>(
    `SELECT key_id, org_id, user_id, issued_at, expires_at, source
     FROM key_session WITH INDEX key_session_by_key_issued
     WHERE key_id = $key_id ${whereSince}
     ORDER BY issued_at DESC
     LIMIT ${limit};`,
    { key_id: keyId, since: opts.since },
  );

  function safeIso(v: unknown): string {
    if (typeof v === 'string' && v.length > 0) return v;
    try { return new Date(v as any).toISOString(); } catch { return new Date(0).toISOString(); }
  }

  const rows: KeySessionRow[] = (Array.isArray(rowResult) ? rowResult : []).flatMap((r: any) => {
    try {
      return [{
        key_id: String(r.key_id),
        org_id: String(r.org_id),
        user_id: r.user_id ? String(r.user_id) : undefined,
        issued_at: safeIso(r.issued_at),
        expires_at: safeIso(r.expires_at),
        source: r.source as KeySessionSource,
      }];
    } catch { return []; }
  });

  // Compute aggregate from the page rows (avoids a second DB query that runs
  // math::sum/min/max over potentially millions of legacy rows with null dates).
  // Count comes from a lightweight COUNT-only query so it reflects full history,
  // not just the current page.  Skip the count entirely for keys with no rows —
  // avoids a 849K-row scan for keys that have never minted a session.
  let totalCount = rows.length;
  if (rows.length > 0) {
    try {
      const countResult = await query<any[]>(
        `SELECT count() AS c FROM key_session WITH INDEX key_session_by_key_issued WHERE key_id = $key_id ${whereSince} GROUP ALL;`,
        { key_id: keyId, since: opts.since },
      );
      const cr = Array.isArray(countResult) ? countResult[0] : undefined;
      if (cr?.c != null) totalCount = Number(cr.c);
    } catch { /* use page length */ }
  }

  let totalEstimatedSeconds = 0;
  let firstSeen: string | undefined;
  let lastSeen: string | undefined;
  for (const row of rows) {
    try {
      const issuedMs = new Date(row.issued_at).getTime();
      const expiresMs = new Date(row.expires_at).getTime();
      if (!isNaN(issuedMs) && !isNaN(expiresMs)) {
        totalEstimatedSeconds += Math.max(0, (expiresMs - issuedMs) / 1000);
      }
      if (!firstSeen || row.issued_at < firstSeen) firstSeen = row.issued_at;
      if (!lastSeen || row.issued_at > lastSeen) lastSeen = row.issued_at;
    } catch { /* skip malformed row */ }
  }

  const aggregate: KeySessionAggregate = {
    key_id: keyId,
    count: totalCount,
    total_estimated_seconds: totalEstimatedSeconds,
    first_seen: firstSeen,
    last_seen: lastSeen,
  };

  return { rows, aggregate };
}
