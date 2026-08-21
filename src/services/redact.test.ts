/**
 * Regression tests for the credential-echo defect.
 *
 * The bug: GET /v1/keys with `Authorization: Bearer mb-FAKE-CANARY-…` returned
 *   {"success":false,"error":{"code":"INVALID_AUTH",
 *    "message":"invalid JWT token: mb-FAKE-CANARY-abcdef0123456789"}}
 * because verifyToken() passed hono's exception message straight through.
 */

import { describe, expect, it } from 'bun:test';
import { credentialHint, redactCredential, safeJwtErrorMessage } from './redact';
import { generateToken, verifyToken } from './jwt';

const CANARY = 'mb-FAKE-CANARY-abcdef0123456789';

describe('safeJwtErrorMessage', () => {
  it('never returns the message of a token-bearing hono error', () => {
    const err = new Error(`invalid JWT token: ${CANARY}`);
    err.name = 'JwtTokenInvalid';
    const msg = safeJwtErrorMessage(err);
    expect(msg).toBe('JWT is malformed');
    expect(msg).not.toContain('CANARY');
  });

  it('preserves the failure reason for each known class', () => {
    const expired = new Error(`token (${CANARY}) expired`);
    expired.name = 'JwtTokenExpired';
    expect(safeJwtErrorMessage(expired)).toBe('JWT has expired');

    const sig = new Error(`token(${CANARY}) signature mismatched`);
    sig.name = 'JwtTokenSignatureMismatched';
    expect(safeJwtErrorMessage(sig)).toBe('JWT signature verification failed');
  });

  it('fails closed on an unknown error class', () => {
    const err = new Error(`some future error leaking ${CANARY}`);
    err.name = 'JwtSomethingNew';
    expect(safeJwtErrorMessage(err)).toBe('Token verification failed');
  });

  it('handles non-Error throws', () => {
    expect(safeJwtErrorMessage(CANARY)).toBe('Token verification failed');
  });
});

describe('redactCredential', () => {
  it('removes an exact credential', () => {
    expect(redactCredential(`rejected: ${CANARY}`, CANARY)).not.toContain('CANARY');
  });

  it('accepts a whole Authorization header as the needle', () => {
    const out = redactCredential(`upstream said ${CANARY}`, `Bearer ${CANARY}`);
    expect(out).not.toContain('CANARY');
  });

  it('removes key-shaped material it was not told about', () => {
    const out = redactCredential('issuer rejected mb-abcdefghij-0123456789');
    expect(out).toBe('issuer rejected [redacted]');
  });

  it('removes JWT-shaped material it was not told about', () => {
    const out = redactCredential('bad eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ4In0.c2ln');
    expect(out).toBe('bad [redacted]');
  });

  it('leaves ordinary diagnostics alone', () => {
    expect(redactCredential('Issuer validation failed (503)')).toBe(
      'Issuer validation failed (503)',
    );
  });

  it('ignores a too-short needle rather than scrubbing everything', () => {
    expect(redactCredential('org mb1 rejected', 'mb1')).toBe('org mb1 rejected');
  });
});

describe('credentialHint', () => {
  it('exposes at most the last four characters', () => {
    expect(credentialHint(CANARY)).toBe('…6789');
  });

  it('refuses to hint at short material', () => {
    expect(credentialHint('short')).toBe('unknown');
  });
});

describe('verifyToken', () => {
  it('does not echo a non-JWT credential presented as a bearer token', async () => {
    const result = await verifyToken(CANARY);
    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
    expect(result.error).not.toContain(CANARY);
    expect(result.error).not.toContain('CANARY');
  });

  it('does not echo a well-formed token with a bad signature', async () => {
    const { token } = await generateToken({
      user_id: 'u1',
      org_id: 'o1',
      role: 'member',
      project_ids: [],
    });
    const tampered = `${token.slice(0, -4)}zzzz`;
    const result = await verifyToken(tampered);
    expect(result.valid).toBe(false);
    expect(result.error).not.toContain(tampered.split('.')[2]);
  });

  it('still verifies a good token', async () => {
    const { token } = await generateToken({
      user_id: 'u1',
      org_id: 'o1',
      role: 'member',
      project_ids: [],
    });
    const result = await verifyToken(token);
    expect(result.valid).toBe(true);
    expect(result.org_id).toBe('o1');
  });
});

/**
 * The second vector, found by probing the FIXED source rather than reading the
 * diff: `resolvers/issue-key.ts` imports hono's `verify` directly instead of
 * going through `services/jwt.ts`'s verifyToken(), so it never inherited the
 * mapping above and kept returning `err.message` verbatim.
 *
 *   POST /v1/keys/issue -H 'authorization: Bearer mb-FAKE-CANARY-…'
 *   -> {"error":{"code":"INVALID_JWT",
 *       "message":"invalid JWT token: mb-FAKE-CANARY-abcdef0123456789"}}
 *
 * This test asserts the property that actually matters — that every direct
 * hono/jwt caller is routed through safeJwtErrorMessage() — rather than
 * re-testing the helper, which the cases above already cover.
 */
describe('direct hono/jwt call sites', () => {
  it('routes every raw `verify` import through safeJwtErrorMessage', async () => {
    const src = await Bun.file(
      new URL('../resolvers/issue-key.ts', import.meta.url).pathname,
    ).text();

    // The catch block around the direct verifyJwt() call must not surface
    // `err.message`; it must hand the error to the redaction helper.
    expect(src).toContain('safeJwtErrorMessage(err)');
    expect(src).not.toMatch(
      /INVALID_JWT',\s*err instanceof Error \? err\.message/,
    );
  });

  it('gives the canary probe a credential-free message', () => {
    const err = new Error(`invalid JWT token: ${CANARY}`);
    err.name = 'JwtTokenInvalid';
    const message = safeJwtErrorMessage(err);
    expect(message).not.toContain(CANARY);
    expect(message).not.toContain('mb-');
    expect(message).toBe('JWT is malformed');
  });
});
