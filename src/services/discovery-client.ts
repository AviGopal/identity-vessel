/**
 * Discovery Vessel Client for Identity-Vessel
 *
 * Special Considerations:
 * - Circular dependency: identity validates discovery, discovery uses identity
 * - Bootstrap delay: 30-second delay before initial registration
 * - Graceful degradation: Operates independently if discovery is unavailable
 */

import { VesselClient, type DiscoveryConfig } from '@metabob/vessel-discovery-client';
import { config } from './config';

/**
 * Create discovery client with bootstrap delay
 */
function createDiscoveryClient(): VesselClient | null {
  if (!config.discovery.enabled) {
    console.log('[Discovery] Discovery integration disabled');
    return null;
  }

  const discoveryConfig: DiscoveryConfig = {
    discoveryEndpoint: config.discovery.endpoint,
    vesselId: config.discovery.vesselId,
    vesselName: 'identity-vessel',
    version: '0.1.0',
    endpoint: getEndpoint(),
    shapes: config.discovery.shapes,
    protocol: 'http',
    heartbeatIntervalMs: config.discovery.heartbeatIntervalMs,
    maxConsecutiveFailures: config.discovery.retryAttempts,
    initialRetryDelayMs: config.discovery.retryBackoffMs,
    metadata: {
      environment: detectEnvironment(),
      podId: process.env.HOSTNAME || 'unknown',
      port: config.port,
      capabilities: ['api-key-generation', 'api-key-validation', 'jwt-validation'],
    },
  };

  return new VesselClient(discoveryConfig);
}

/**
 * Get this vessel's external endpoint
 */
function getEndpoint(): string {
  // Use explicit endpoint if configured
  if (process.env.VESSEL_ENDPOINT) {
    return process.env.VESSEL_ENDPOINT;
  }

  // In Kubernetes, construct from service name
  const namespace = process.env.SURREALDB_NAMESPACE || 'activity-system';
  const serviceName = process.env.SERVICE_NAME || 'identity-vessel';
  const port = config.port;

  return `http://${serviceName}.${namespace}.svc.cluster.local:${port}`;
}

/**
 * Detect deployment environment
 */
function detectEnvironment(): 'k8s-cluster' | 'docker' | 'local' {
  if (process.env.KUBERNETES_SERVICE_HOST) {
    return 'k8s-cluster';
  } else if (process.env.DOCKER_CONTAINER) {
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
