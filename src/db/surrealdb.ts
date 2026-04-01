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
