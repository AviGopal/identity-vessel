// C6 regression: a substrate must validate its OWN default-issuer keys LOCALLY,
// even when IDENTITY_ENDPOINT (SELF_ISSUER) differs from the keyGeneration default.
// This is the 401-on-registration bug: existing keys carry iss=https://identity.metabob.com
// (minted before IDENTITY_ENDPOINT was set) but SELF_ISSUER is the local URL.
process.env.IDENTITY_ENDPOINT = 'http://127.0.0.1:8101'; // SELF_ISSUER != default
process.env.API_KEY_SECRET = 'dev-secret-change-in-production';
import { test, expect, describe } from 'bun:test';
import { createHmac } from 'crypto';
import { validateKey, setQueryFn } from './validation';

function defaultIssuerKey(): string {
  const payload = `metabob_com-users:svc-key_svc001-https://identity.metabob.com`;
  const enc = Buffer.from(payload).toString('base64url');
  const fin = `mb-${enc}`;
  const sig = createHmac('sha256', 'dev-secret-change-in-production').update(fin).digest('hex').slice(0, 32);
  return `${fin}-${sig}`;
}

describe('C6 self-issuer', () => {
  test('default-issuer key validates locally (not delegated as foreign)', async () => {
    setQueryFn(async () => [{ result: [{ scopes: ['read'] }] }]); // mock DB scope lookup
    const r = await validateKey(defaultIssuerKey());
    setQueryFn(null);
    expect(r.error || '').not.toContain('Untrusted'); // the bug returned "Untrusted key issuer"
    expect(r.valid).toBe(true);
  });
});
