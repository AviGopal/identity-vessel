/**
 * identity's own authentication traces are written under identity's CREDENTIAL org; the org being authenticated is
 * the trace's SUBJECT and goes in metadata, never in the trace's org.
 *
 * activity-api takes a trace's org from the caller's validated credential. A body org_id is only a claim: equal to the
 * caller's org it lands, naming any other org it is refused with 403 ORG_MISMATCH and nothing is stored. identity
 * posts these traces with its own API key, so a body `org_id` naming the authenticated org (or 'unknown') would be
 * refused for every cross-org or anonymous authentication.
 *
 * HERMETIC BY PROCESS. Each case runs in a fresh child bun process (trace-org.fixture.ts) holding a loopback stub of
 * that activity-api. In a one-process whole suite another file mock.module()s ./trace process-wide, and the trace
 * module reads its endpoint at import, so an in-process version of this test saw a stubbed or stale trace module and
 * went red on every case, the control included. The child sees none of that; it prints one result line we assert on.
 */
import { describe, expect, it } from 'bun:test';
import { join } from 'node:path';
import { CREDENTIAL_ORG } from './trace-org.fixture';

const strip = (o: string) => o.replace(/^organizations:/, '');
const FIXTURE = join(import.meta.dir, 'trace-org.fixture.ts');
// A child bun start under nice and a loaded host has taken ~3s; the 5s default would turn load into a false red.
const CHILD_TIMEOUT_MS = 30_000;

type Result = { refusals: number; stored: Array<{ org_id: string; body: Record<string, any> }> };

async function runCase(which: 'different' | 'unknown' | 'same'): Promise<Result> {
  const proc = Bun.spawn([process.execPath, 'run', FIXTURE, which], {
    cwd: import.meta.dir,
    // A minimal env: nothing from this process (keys, endpoints, sampling flags) reaches the child.
    env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '/tmp' },
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const [out, err, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);
  const line = out.split('\n').find((l) => l.startsWith('TRACE_ORG_RESULT '));
  if (code !== 0 || !line) throw new Error(`fixture ${which} exited ${code} with no result line\n${out}\n${err}`);
  return JSON.parse(line.slice('TRACE_ORG_RESULT '.length)) as Result;
}

describe('identity auth traces: credential org owns the trace, the subject org rides in metadata', () => {
  it('MUST-FAIL: an auth trace for a DIFFERENT subject org is accepted and names the subject in metadata', async () => {
    const r = await runCase('different');
    expect(r.refusals).toBe(0);
    expect(r.stored.length).toBe(1);
    expect(strip(r.stored[0]!.org_id)).toBe(strip(CREDENTIAL_ORG));
    expect(r.stored[0]!.body.metadata?.subject_org_id).toBe('organizations:tenant-b');
  }, CHILD_TIMEOUT_MS);

  it("MUST-FAIL: an auth trace with no subject org is accepted and records 'unknown' as the subject in metadata", async () => {
    const r = await runCase('unknown');
    expect(r.refusals).toBe(0);
    expect(r.stored.length).toBe(1);
    expect(strip(r.stored[0]!.org_id)).toBe(strip(CREDENTIAL_ORG));
    expect(r.stored[0]!.body.metadata?.subject_org_id).toBe('unknown');
  }, CHILD_TIMEOUT_MS);

  it("CONTROL: a same-org auth trace is accepted under identity's own org with its trace fields unchanged", async () => {
    const r = await runCase('same');
    expect(r.refusals).toBe(0);
    expect(r.stored.length).toBe(1);
    const b = r.stored[0]!.body;
    expect(strip(r.stored[0]!.org_id)).toBe(strip(CREDENTIAL_ORG));
    expect(b.template_id).toBe('auth_resolve_v1');
    expect(b.status).toBe('failure');
    expect(b.success).toBe(false);
    expect(b.user_id).toBe('users:u1');
    expect(b.error_message).toBe('x');
    expect(b.tags).toEqual(['identity-vessel', 'reached:false', 'telemetry:auth', 'auth:failure']);
    expect(b.metadata?.activity_type).toBe('authentication_resolution');
    expect(b.metadata?.key_id).toBe('kid-test');
  }, CHILD_TIMEOUT_MS);
});
