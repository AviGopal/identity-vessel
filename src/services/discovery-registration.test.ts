/**
 * identity's discovery registration routes its shapes to the door that serves them, and is
 * authenticated, so discovery accepts it and a reader resolving apiKeyClass by shape finds it.
 *
 * MUST-FAIL on a tree without it: the registration carried no credential (discovery answered
 * 401 and identity gave up) and no resolve_endpoint (discovery routes to a path identity does
 * not serve). The service key below is a fixture string, never a real key.
 */

import { test, expect, describe } from 'bun:test';
import { buildDiscoveryConfig, getEndpoint, RESOLVE_PATH } from './discovery-client';
import { config } from './config';

const FIXTURE_KEY = 'fixture-service-key-not-real';

describe('discovery registration', () => {
  test('advertises apiKeyClass with identity\'s other shapes, routed to the resolve door with ApiKey auth', () => {
    const c = buildDiscoveryConfig({ METABOB_API_KEY: FIXTURE_KEY });
    expect(c.shapes).toEqual(['authentication', 'apiKey_write', 'apiKeyClass']);
    expect(RESOLVE_PATH).toBe('/v1/auth/resolve');
    expect(c.resolve_endpoint).toBe('/v1/auth/resolve');
    expect(c.resolve_request_format).toBe('pointer');
    expect(c.auth_scheme).toBe('ApiKey');
    expect(c.authType).toBe('ApiKey');
    expect(c.authToken).toBe(FIXTURE_KEY);
  });

  test('with no service key it registers without a credential rather than an empty one', () => {
    const c = buildDiscoveryConfig({});
    expect(c.authToken).toBeUndefined();
    expect(c.authType).toBeUndefined();
  });

  test('the endpoint is the explicit one, else the advertise host, else this process, and a cluster name only in Kubernetes', () => {
    expect(getEndpoint({ VESSEL_ENDPOINT: 'http://fixture.invalid:1/' })).toBe('http://fixture.invalid:1');
    expect(getEndpoint({ VESSEL_ADVERTISE_ENDPOINT: 'http://fixture-adv.invalid:2' })).toBe('http://fixture-adv.invalid:2');
    expect(getEndpoint({ SUBSTRATE_ADVERTISE_HOST: 'fixture-host.invalid' })).toBe(`http://fixture-host.invalid:${config.port + 10_000}`);
    expect(getEndpoint({ KUBERNETES_SERVICE_HOST: 'x' })).toContain('.svc.cluster.local:');
    expect(getEndpoint({})).toBe(`http://${config.host === '0.0.0.0' ? 'localhost' : config.host}:${config.port}`);
  });
});
