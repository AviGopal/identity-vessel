/**
 * Dual-secret (rotation-window) validation tests.
 * A key is SIGNED with the current API_KEY_SECRET only, but ACCEPTED if it
 * verifies under the current secret OR any previous rotation-window secret.
 */
import { test, expect, describe } from 'bun:test';
import { createHmac } from 'crypto';
import { parseApiKey, verifySignature, validateKeyFormat } from './validation';
import { generateApiKey } from './keyGeneration';

const SECRET_OLD = 'secret-old-rotation-window';
const SECRET_NEW = 'secret-new-current';
const SECRET_UNRELATED = 'secret-attacker-unrelated';
const ISS = 'https://identity.metabob.com';

function signKeyWith(secret: string, orgId = 'testorg', userId = 'users:testuser', keyId = 'key_abc123def456'): string {
  const signedPayload = `${orgId}-${userId}-${keyId}-${ISS}`;
  const encodedPayload = Buffer.from(signedPayload).toString('base64url');
  const finalPayload = `mb-${encodedPayload}`;
  const signature = createHmac('sha256', secret).update(finalPayload).digest('hex').slice(0, 32);
  return `${finalPayload}-${signature}`;
}

describe('Dual-secret rotation-window validation', () => {
  test('(a) old-signed key validates when secrets=[NEW, OLD]', () => {
    const c = parseApiKey(signKeyWith(SECRET_OLD));
    expect(c).not.toBeNull();
    expect(verifySignature(c!, [SECRET_NEW, SECRET_OLD])).toBe(true);
  });
  test('(b) new-signed key validates when secrets=[NEW, OLD]', () => {
    const c = parseApiKey(signKeyWith(SECRET_NEW));
    expect(c).not.toBeNull();
    expect(verifySignature(c!, [SECRET_NEW, SECRET_OLD])).toBe(true);
  });
  test('(c) unrelated-secret key does NOT validate against [NEW, OLD]', () => {
    const c = parseApiKey(signKeyWith(SECRET_UNRELATED));
    expect(c).not.toBeNull();
    expect(verifySignature(c!, [SECRET_NEW, SECRET_OLD])).toBe(false);
  });
  test('(d) old-signed key FAILS when secrets=[NEW] only', () => {
    const c = parseApiKey(signKeyWith(SECRET_OLD));
    expect(c).not.toBeNull();
    expect(verifySignature(c!, [SECRET_NEW])).toBe(false);
  });
});
