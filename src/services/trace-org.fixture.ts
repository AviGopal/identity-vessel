/**
 * Child-process fixture for trace-org.test.ts. Not a test file: the test spawns it in a fresh bun process, so no other
 * test file sharing the suite process can reach it (a process-wide mock.module of ./trace, a swapped globalThis.fetch,
 * or a trace module already imported with another ACTIVITY_API_ENDPOINT).
 *
 * It stands up a stub of the trace endpoint on 127.0.0.1 at an ephemeral port, behaving like activity-api that takes
 * a trace's org from the caller's credential: only the test key is accepted, the org is the key's, and a body org_id
 * naming another org is refused with 403 ORG_MISMATCH and nothing is stored. It then sends one authentication trace
 * for the case named in argv and prints ONE line: `TRACE_ORG_RESULT <json>`.
 *
 * usage: bun run trace-org.fixture.ts <different|unknown|same>
 */
export const TEST_KEY = 'test-only-identity-trace-key';
export const CREDENTIAL_ORG = 'organizations:identity-own';
const strip = (o: string) => o.replace(/^organizations:/, '');

type Stored = { org_id: string; body: Record<string, any> };

async function main(which: string): Promise<void> {
  const stored: Stored[] = [];
  let refusals = 0;
  const server = Bun.serve({
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

  try {
    // trace.ts reads its endpoint and key at import/use time; set both before the first import in this process.
    for (const k of ['METABOB_API_KEY', 'INTERNAL_API_KEY', 'TRACE_SAMPLE_RATE', 'ALWAYS_TRACE_FAILURES']) delete process.env[k];
    process.env.SUBSTRATE_API_KEY = TEST_KEY;
    process.env.ACTIVITY_API_ENDPOINT = `http://127.0.0.1:${server.port}`;
    const { sendAuthenticationTrace } = await import('./trace');

    // A failure is always traced (ALWAYS_TRACE_FAILURES defaults on), so sampling cannot skip it.
    const base = { activityType: 'authentication_resolution' as const, startTime: 1, endTime: 2, durationMs: 1, success: false, error: 'x' };
    if (which === 'different') await sendAuthenticationTrace({ ...base, orgId: 'organizations:tenant-b' });
    else if (which === 'unknown') await sendAuthenticationTrace(base);
    else if (which === 'same') await sendAuthenticationTrace({ ...base, orgId: CREDENTIAL_ORG, userId: 'users:u1', keyId: 'kid-test' });
    else throw new Error(`unknown case ${which}`);

    console.log(`TRACE_ORG_RESULT ${JSON.stringify({ refusals, stored })}`);
  } finally {
    server.stop(true);
  }
}

if (import.meta.main) {
  await main(process.argv[2] ?? '');
}
