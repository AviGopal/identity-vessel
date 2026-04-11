/**
 * Centralized configuration for identity-vessel
 * Single source of truth for environment variables
 */

export interface IdentityVesselConfig {
  // Server configuration
  port: number;
  host: string;

  // SurrealDB configuration
  surrealdb: {
    url: string;
    namespace: string;
    database: string;
    username: string;
    password: string;
  };

  // Redis for revocation storage
  redis: {
    url: string;
    ttl: number; // Revocation TTL (1 year default)
  };

  // HMAC key for API key signing
  hmac: {
    secret: string;
  };

  // Discovery Vessel Integration
  // Special consideration: circular dependency with discovery
  // (identity validates discovery, discovery uses identity)
  discovery: {
    enabled: boolean;
    endpoint: string;
    vesselId: string;
    heartbeatIntervalMs: number;
    retryAttempts: number;
    retryBackoffMs: number;
    bootstrapDelayMs: number; // Delay before initial registration (30s default)
    shapes: string[];
  };
}

function parseEnvInt(key: string, defaultValue: number): number {
  const value = process.env[key];
  return value ? parseInt(value, 10) : defaultValue;
}

function parseEnvBool(key: string, defaultValue: boolean): boolean {
  const value = process.env[key];
  if (!value) return defaultValue;
  return value.toLowerCase() === 'true' || value === '1';
}

/**
 * Generates vessel ID from environment variables
 * Uses VESSEL_ID if set, otherwise generates from hostname
 */
function generateVesselId(): string {
  if (process.env.VESSEL_ID) {
    return process.env.VESSEL_ID;
  }

  const hostname = process.env.HOSTNAME || 'identity-vessel';
  const podName = process.env.POD_NAME || hostname;

  return `identity-vessel-${podName}`;
}

/**
 * Load and validate environment variables
 */
export function loadConfig(): IdentityVesselConfig {
  return {
    port: parseEnvInt('PORT', 8080),
    host: process.env.HOST || '0.0.0.0',

    surrealdb: {
      url: process.env.SURREALDB_URL || 'http://surrealdb.activity-system.svc.cluster.local:8000',
      namespace: process.env.SURREALDB_NAMESPACE || 'activity-system',
      database: process.env.SURREALDB_DATABASE || 'learning_loop',
      username: process.env.SURREALDB_USERNAME || '',
      password: process.env.SURREALDB_PASSWORD || '',
    },

    redis: {
      url: process.env.REDIS_URL || 'redis://localhost:6379',
      ttl: parseEnvInt('REDIS_REVOCATION_TTL', 31536000), // 1 year
    },

    hmac: {
      secret: process.env.HMAC_SECRET || 'dev-hmac-secret-change-in-production',
    },

    discovery: {
      enabled: parseEnvBool('DISCOVERY_ENABLED', true),
      endpoint: process.env.DISCOVERY_VESSEL_ENDPOINT || 'http://discovery-vessel.activity-system.svc.cluster.local:8080',
      vesselId: generateVesselId(),
      heartbeatIntervalMs: parseEnvInt('DISCOVERY_HEARTBEAT_INTERVAL_MS', 60000), // 60 seconds
      retryAttempts: parseEnvInt('DISCOVERY_RETRY_ATTEMPTS', 3),
      retryBackoffMs: parseEnvInt('DISCOVERY_RETRY_BACKOFF_MS', 1000),
      bootstrapDelayMs: parseEnvInt('DISCOVERY_BOOTSTRAP_DELAY_MS', 30000), // 30 seconds
      shapes: [
        'authentication',
        'apiKey',
        'jwtToken',
      ],
    },
  };
}

// Export singleton config instance
export const config = loadConfig();
