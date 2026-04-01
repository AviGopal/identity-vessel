/**
 * Centralized configuration for identity-vessel
 * Single source of truth for environment variables
 */

export interface IdentityVesselConfig {
  // Server configuration
  port: number;

  // SurrealDB configuration
  surrealdb: {
    url: string;
    namespace: string;
    database: string;
    username: string;
    password: string;
  };
}

/**
 * Load and validate environment variables
 */
export function loadConfig(): IdentityVesselConfig {
  return {
    port: parseInt(process.env.PORT || '8080'),

    surrealdb: {
      url: process.env.SURREALDB_URL || 'http://surrealdb.activity-system.svc.cluster.local:8000',
      namespace: process.env.SURREALDB_NAMESPACE || 'activity-system',
      database: process.env.SURREALDB_DATABASE || 'learning_loop',
      username: process.env.SURREALDB_USERNAME || '',
      password: process.env.SURREALDB_PASSWORD || '',
    }
  };
}

// Export singleton config instance
export const config = loadConfig();
