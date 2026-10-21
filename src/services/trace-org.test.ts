/**
 * identity's own authentication traces are written under identity's CREDENTIAL org; the org being authenticated is
 * the trace's SUBJECT and goes in metadata, never in the trace's org.
 *
 * activity-api takes a trace's org from the caller's validated credential. A body org_id is only a claim: equal to the
 * caller's org it lands, naming any other org it is refused with 403 ORG_MISMATCH and nothing is stored. identity
 * posts these traces with its own API key, so a body `org_id` naming the authenticated org (or 'unknown') would be
 * refused for every cross-org or anonymous authentication.
 *
 * The stub below behaves like that activity-api: it binds 127.0.0.1 on an ephemeral port, accepts only the test key,
 * resolves the org from that key, and refuses a differing body org. No live service, no real key.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'bun:test';

const TEST_KEY = 'test-only-identity-trace-key';
const CREDENTIAL_ORG = 'organizations:identity-own';
const strip = (o: string) => o.replace(/^organizations:/, '');

type Stored = { org_id: string; body: Record<string, any> };
let stored: Stored[] = [];
let refusals: number = 0;
let server: ReturnType<typeof Bun.serve>;

const ENV_KEYS = ['SUBSTRATE_API_KEY', 'METABOB_API_KEY', 'INTERNAL_API_KEY', 'TRACE_SAMPLE_RATE', 'ALWAYS_TRACE_FAILURES', 'ACTIVITY_API_ENDPOINT'] as const;
const saved: Record<string, string | undefined> = {};

beforeAll(() => {
  server = Bun.serve({
    hostname: '127.0.0.1',
    port: 0,
    async fetch(req) {
      if (new URL(req.url).pathname !== '/v2/activities/execution-traces' || req.method !== 'POST') {
        return new Response('not found', { status: 404 });
      }
      if (req.headers.get('authorization') !== `ApiKey ${TEST_KEY}`) {
        return Response.json({ error: { code: 'UNAUTHORIZED' } }, { status: 401 });
      }
      const body = (await req.json()) as Record<string, any>;
      const bodyOrg = body.org_id;
      if (bodyOrg !== undefined && bodyOrg !== null && strip(String(bodyOrg)) !== strip(CREDENTIAL_ORG)) {
        refusals += 1;
        return Response.json({ error: { code: 'ORG_MISMATCH', message: `body org_id "${bodyOrg}" is not the caller's` } }, { status: 403 });
      }
      stored.push({ org_id: bodyOrg ?? CREDENTIAL_ORG, body });
      return Response.json({ success: true }, { status: 201 });
    },
  });
});
afterAll(() => { server.stop(true); });

beforeEach(() => {
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  process.env.SUBSTRATE_API_KEY = TEST_KEY;
  // trace.ts reads its endpoint at import; set it before the first dynamic import below.
  process.env.ACTIVITY_API_ENDPOINT = `http://127.0.0.1:${server.port}`;
  stored = [];
  refusals = 0;
});
afterEach(() => {
  for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
});

// A failure is always traced (ALWAYS_TRACE_FAILURES defaults on), so sampling cannot skip it.
const failure = (orgId?: string) => ({
  activityType: 'authentication_resolution' as const, startTime: 1, endTime: 2, durationMs: 1, success: false, error: 'x',
  ...(orgId === undefined ? {} : { orgId }),
});

describe('identity auth traces: credential org owns the trace, the subject org rides in metadata', () => {
  it('MUST-FAIL: an auth trace for a DIFFERENT subject org is accepted and names the subject in metadata', async () => {
    const { sendAuthenticationTrace } = await import('./trace');
    await sendAuthenticationTrace(failure('organizations:tenant-b'));
    expect(refusals).toBe(0);
    expect(stored.length).toBe(1);
    expect(strip(stored[0]!.org_id)).toBe(strip(CREDENTIAL_ORG));
    expect(stored[0]!.body.metadata?.subject_org_id).toBe('organizations:tenant-b');
  });

  it("MUST-FAIL: an auth trace with no subject org is accepted and records 'unknown' as the subject in metadata", async () => {
    const { sendAuthenticationTrace } = await import('./trace');
    await sendAuthenticationTrace(failure());
    expect(refusals).toBe(0);
    expect(stored.length).toBe(1);
    expect(strip(stored[0]!.org_id)).toBe(strip(CREDENTIAL_ORG));
    expect(stored[0]!.body.metadata?.subject_org_id).toBe('unknown');
  });

  it("CONTROL: a same-org auth trace is accepted under identity's own org with its trace fields unchanged", async () => {
    const { sendAuthenticationTrace } = await import('./trace');
    await sendAuthenticationTrace({ ...failure(CREDENTIAL_ORG), userId: 'users:u1', keyId: 'kid-test' });
    expect(refusals).toBe(0);
    expect(stored.length).toBe(1);
    const b = stored[0]!.body;
    expect(strip(stored[0]!.org_id)).toBe(strip(CREDENTIAL_ORG));
    expect(b.template_id).toBe('auth_resolve_v1');
    expect(b.status).toBe('failure');
    expect(b.success).toBe(false);
    expect(b.user_id).toBe('users:u1');
    expect(b.error_message).toBe('x');
    expect(b.tags).toEqual(['identity-vessel', 'reached:false', 'telemetry:auth', 'auth:failure']);
    expect(b.metadata?.activity_type).toBe('authentication_resolution');
    expect(b.metadata?.key_id).toBe('kid-test');
  });
});
