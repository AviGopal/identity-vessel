/**
 * Discovery Vessel Client for Identity-Vessel
 *
 * Special Considerations:
 * - Circular dependency: identity validates discovery, discovery uses identity
 * - Bootstrap delay: 30-second delay before initial registration
 * - Graceful degradation: Operates independently if discovery is unavailable
 */

import { VesselClient, type DiscoveryConfig } from '@avigopal/vessel-discovery-client';
import { config } from './config';

/** The path discovery routes identity's shapes to: identity's one resolve door. */
export const RESOLVE_PATH = '/v1/auth/resolve';

/**
 * The registration identity sends discovery. Discovery refuses an unauthenticated register
 * (401), so it carries this vessel's service key (METABOB_API_KEY, the credential every vessel
 * registers with) as an ApiKey; never logged. resolve_endpoint names identity's resolve door,
 * which is where every shape below is served: without it discovery routes them to its default
 * path, which identity does not serve. Exported for tests.
 */
export function buildDiscoveryConfig(env: Record<string, string | undefined> = process.env): DiscoveryConfig {
  const apiKey = (env.METABOB_API_KEY ?? '').trim();
  return {
    discoveryEndpoint: config.discovery.endpoint,
    vesselId: config.discovery.vesselId,
    vesselName: 'identity-vessel',
    version: '0.1.0',
    endpoint: getEndpoint(env),
    shapes: config.discovery.shapes,
    protocol: 'http',
    heartbeatIntervalMs: config.discovery.heartbeatIntervalMs,
    maxConsecutiveFailures: config.discovery.retryAttempts,
    initialRetryDelayMs: config.discovery.retryBackoffMs,
    metadata: {
      environment: detectEnvironment(env),
      podId: env.HOSTNAME || 'unknown',
      port: config.port,
      capabilities: ['api-key-generation', 'api-key-validation', 'jwt-validation'],
    },
    ...(apiKey ? { authToken: apiKey, authType: 'ApiKey' as const } : {}),
    resolve_endpoint: RESOLVE_PATH,
    resolve_request_format: 'pointer',
    auth_scheme: 'ApiKey',
  };
}

/**
 * Create discovery client with bootstrap delay
 */
function createDiscoveryClient(): VesselClient | null {
  if (!config.discovery.enabled) {
    console.log('[Discovery] Discovery integration disabled');
    return null;
  }
  return new VesselClient(buildDiscoveryConfig());
}

/**
 * Get this vessel's external endpoint: an explicit VESSEL_ENDPOINT or VESSEL_ADVERTISE_ENDPOINT,
 * else the advertise host with the published port offset (the rule the other vessels register
 * with), else the cluster service name in Kubernetes, else this process's own host and port.
 */
export function getEndpoint(env: Record<string, string | undefined> = process.env): string {
  const explicit = (env.VESSEL_ENDPOINT || env.VESSEL_ADVERTISE_ENDPOINT || '').replace(/\/+$/, '');
  if (explicit) return explicit;

  const port = config.port;
  if (env.SUBSTRATE_ADVERTISE_HOST) {
    return `http://${env.SUBSTRATE_ADVERTISE_HOST}:${port + Number(env.SUBSTRATE_ADVERTISE_PORT_OFFSET ?? 10_000)}`;
  }

  if (env.KUBERNETES_SERVICE_HOST) {
    const namespace = env.SURREALDB_NAMESPACE || 'activity-system';
    const serviceName = env.SERVICE_NAME || 'identity-vessel';
    return `http://${serviceName}.${namespace}.svc.cluster.local:${port}`;
  }

  return `http://${config.host === '0.0.0.0' ? 'localhost' : config.host}:${port}`;
}

/**
 * Detect deployment environment
 */
function detectEnvironment(env: Record<string, string | undefined> = process.env): 'k8s-cluster' | 'docker' | 'local' {
  if (env.KUBERNETES_SERVICE_HOST) {
    return 'k8s-cluster';
  } else if (env.DOCKER_CONTAINER) {
    return 'docker';
  } else {
    return 'local';
  }
}

/**
 * Register with discovery-vessel after bootstrap delay
 *
 * This function implements the bootstrap delay to avoid circular dependency:
 * 1. Identity-vessel starts and becomes available
 * 2. Discovery-vessel can use identity for authentication
 * 3. After delay, identity-vessel registers with discovery
 */
export async function registerWithDiscoveryAfterDelay(client: VesselClient): Promise<void> {
  const delayMs = config.discovery.bootstrapDelayMs;

  console.log(`[Discovery] Waiting ${delayMs}ms before registration (bootstrap delay)`);
  console.log('[Discovery] This allows discovery-vessel to use identity for authentication first');

  await new Promise(resolve => setTimeout(resolve, delayMs));

  console.log('[Discovery] Bootstrap delay complete, attempting registration');

  const success = await client.register();

  if (success) {
    console.log('[Discovery] ✓ Initial registration successful');
  } else {
    console.warn('[Discovery] ✗ Initial registration failed (will retry via heartbeat)');
  }
}

// Export singleton instance
export const discoveryClient = createDiscoveryClient();
