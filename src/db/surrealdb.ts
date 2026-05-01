/**
 * SurrealDB connection for user/org storage
 */

import { Surreal } from 'surrealdb';
import { config } from '../services/config';

let db: Surreal | null = null;

/**
 * Get or create SurrealDB connection
 */
export async function getSurrealDB(): Promise<Surreal> {
  if (db) {
    return db;
  }

  try {
    db = new Surreal();

    console.log(`[SurrealDB] Connecting to ${config.surrealdb.url}...`);

    await db.connect(config.surrealdb.url);

    // SurrealDB v3.0.0: Use namespace/database BEFORE signin
    await db.use({
      namespace: config.surrealdb.namespace,
      database: config.surrealdb.database
    });

    // Only signin if credentials are provided (SurrealDB might have auth disabled)
    if (config.surrealdb.username && config.surrealdb.password && config.surrealdb.username !== 'none') {
      await db.signin({
        username: config.surrealdb.username,
        password: config.surrealdb.password
      });
      console.log('[SurrealDB] Signed in as root user');
    }

    console.log('[SurrealDB] Connected successfully');

    return db;
  } catch (error) {
    console.error('[SurrealDB] Connection error:', error);
    throw error;
  }
}

/**
 * Detect auth-state-lost errors that mean our cached connection has lost
 * its signin context (e.g. SurrealDB pod restarted while we held the
 * client). The driver auto-reconnects but does not re-signin, so every
 * subsequent query lands as anonymous and trips PERMISSIONS clauses.
 */
function isAuthStateLostError(err: unknown): boolean {
  if (!err) return false;
  const msg = err instanceof Error ? err.message : String(err);
  // Cover both the message and the structured `kind:"Auth"` field that the
  // SurrealDB driver embeds in its error string.
  return /Anonymous access not allowed|Not enough permissions|kind:\s*['"]?Auth['"]?/i.test(msg);
}

/**
 * Force-discard the cached connection so the next getSurrealDB() builds a
 * fresh one (which re-runs connect → use → signin).
 */
async function resetSurrealDB(): Promise<void> {
  const stale = db;
  db = null;
  if (stale) {
    try {
      await stale.close();
    } catch {
      // ignore — we're throwing this connection away anyway
    }
  }
}

/**
 * Execute a query with error handling. If the cached connection has lost
 * its auth state (typically because SurrealDB restarted underneath us),
 * reset the singleton and retry once with a fresh connect+signin.
 */
export async function query<T = any>(
  sql: string,
  params?: Record<string, any>,
): Promise<T> {
  return queryInternal<T>(sql, params, false);
}

async function queryInternal<T = any>(
  sql: string,
  params: Record<string, any> | undefined,
  isRetry: boolean,
): Promise<T> {
  const connection = await getSurrealDB();

  try {
    const result = await connection.query(sql, params);

    // SurrealDB returns an array of result sets
    // For most queries, we want the first result set
    if (Array.isArray(result) && result.length > 0) {
      return result[0] as T;
    }

    return result as T;
  } catch (error) {
    if (!isRetry && isAuthStateLostError(error)) {
      console.warn('[SurrealDB] auth state lost — resetting connection and retrying once');
      await resetSurrealDB();
      return queryInternal<T>(sql, params, true);
    }
    console.error('[SurrealDB] Query error:', error);
    console.error('[SurrealDB] Query:', sql);
    console.error('[SurrealDB] Params:', params);
    throw error;
  }
}
