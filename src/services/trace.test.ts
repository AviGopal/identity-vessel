/**
 * identity's authentication traces post with an AUTHENTICATED credential (check-first, harm-stop).
 *
 * activity-api let a request with no Authorization header post /v2/activities/execution-traces when it carried an
 * X-Internal-Api-Key header, checked for PRESENCE only, never against a secret. identity was its trace caller and sent
 * `X-Internal-Api-Key: INTERNAL_API_KEY ?? METABOB_API_KEY ?? 'identity-vessel'`. The hub's activity-api is reachable from
 * the internet (2026-10-07), so that path let anyone inject traces into the learning store. activity-api removes the
 * header path next; identity must post with `Authorization: ApiKey <key>` first, and with no key post nothing (counted),
 * never a literal.
 */
import { afterEach, beforeEach, describe, expect, it } from 'bun:test';

const KEYS = ['SUBSTRATE_API_KEY', 'METABOB_API_KEY', 'INTERNAL_API_KEY', 'TRACE_SAMPLE_RATE', 'ALWAYS_TRACE_FAILURES'] as const;
const saved: Record<string, string | undefined> = {};
const realFetch = globalThis.fetch;
let calls: Array<{ url: string; headers: Record<string, string> }> = [];

beforeEach(() => {
  for (const k of KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  calls = [];
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    calls.push({ url: String(url), headers: Object.fromEntries(new Headers(init?.headers).entries()) });
    return new Response('{}', { status: 201 });
  }) as unknown as typeof fetch;
});
afterEach(() => {
  for (const k of KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
  globalThis.fetch = realFetch;
});

// A failure is always traced (ALWAYS_TRACE_FAILURES defaults on), so sampling cannot skip it.
const failure = () => ({ activityType: 'authentication_resolution' as const, startTime: 1, endTime: 2, durationMs: 1, success: false, error: 'x' });

describe('identity authentication traces are authenticated', () => {
  it('MUST-FAIL: posts with Authorization: ApiKey <fleet key> and no X-Internal-Api-Key header', async () => {
    process.env.METABOB_API_KEY = 'mb-test-fleet-key';
    const { sendAuthenticationTrace } = await import('./trace');
    await sendAuthenticationTrace(failure());
    expect(calls.length).toBe(1);
    expect(calls[0]!.headers['authorization']).toBe('ApiKey mb-test-fleet-key');
    expect(calls[0]!.headers['x-internal-api-key']).toBeUndefined();
  });

  it('MUST-FAIL: with no key it posts nothing and counts the skip (no literal fallback)', async () => {
    const mod = await import('./trace');
    const before = mod.authTracesSkippedNoKey();
    await mod.sendAuthenticationTrace(failure());
    expect(calls.length).toBe(0);
    expect(mod.authTracesSkippedNoKey()).toBe(before + 1);
  });

  it('prefers SUBSTRATE_API_KEY (the rename alias) over METABOB_API_KEY', async () => {
    process.env.SUBSTRATE_API_KEY = 'mb-new-name';
    process.env.METABOB_API_KEY = 'mb-old-name';
    const { sendAuthenticationTrace } = await import('./trace');
    await sendAuthenticationTrace(failure());
    expect(calls[0]!.headers['authorization']).toBe('ApiKey mb-new-name');
  });
});
