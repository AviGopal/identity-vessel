/**
 * SurrealDB connection for user/org storage
 */

import { Surreal } from 'surrealdb';

const SURREALDB_URL = process.env.SURREALDB_URL || 'http://surrealdb.activity-system.svc.cluster.local:8000';
const SURREALDB_NAMESPACE = process.env.SURREALDB_NAMESPACE || 'activity-system';
const SURREALDB_DATABASE = process.env.SURREALDB_DATABASE || 'learning_loop';
const SURREALDB_USERNAME = process.env.SURREALDB_USERNAME || '';
const SURREALDB_PASSWORD = process.env.SURREALDB_PASSWORD || '';

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

    console.log(`[SurrealDB] Connecting to ${SURREALDB_URL}...`);

    await db.connect(SURREALDB_URL);

    // SurrealDB v3.0.0: Use namespace/database BEFORE signin
    await db.use({
      namespace: SURREALDB_NAMESPACE,
      database: SURREALDB_DATABASE
    });

    // Only signin if credentials are provided (SurrealDB might have auth disabled)
    if (SURREALDB_USERNAME && SURREALDB_PASSWORD && SURREALDB_USERNAME !== 'none') {
      await db.signin({
        username: SURREALDB_USERNAME,
        password: SURREALDB_PASSWORD
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
 * Execute a query with error handling
 */
export async function query<T = any>(
  sql: string,
  params?: Record<string, any>
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
    console.error('[SurrealDB] Query error:', error);
    console.error('[SurrealDB] Query:', sql);
    console.error('[SurrealDB] Params:', params);
    throw error;
  }
}
