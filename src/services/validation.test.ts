/**
 * Tests for API key validation
 */

import { test, expect, describe } from 'bun:test';
import { parseApiKey, validateKeyFormat, verifySignature } from './validation';
import { generateApiKey } from './keyGeneration';

describe('API Key Validation', () => {
  test('should parse valid API key format', () => {
    // Generate a key with known values
    const generated = generateApiKey('testorg', 'users:testuser', {});
    const result = parseApiKey(generated.key);

    expect(result).not.toBeNull();
    expect(result?.prefix).toBe('mb');
    expect(result?.orgId).toBe('testorg');
    expect(result?.userId).toBe('users:testuser');
    expect(result?.keyId).toBe(generated.keyId);
  });

  test('should reject key without mb- prefix', () => {
    const key = 'pk-somebase64data-signature';
    const result = parseApiKey(key);

    expect(result).toBeNull();
  });

  test('should reject key with invalid base64 payload', () => {
    const key = 'mb-!!!invalid!!!-signature';
    const result = parseApiKey(key);

    expect(result).toBeNull();
  });

  test('should reject malformed key with missing parts', () => {
    const key = 'mb-onlyonepart';
    const result = parseApiKey(key);

    expect(result).toBeNull();
  });

  test('should validate generated key successfully', () => {
    const generated = generateApiKey('metabob_com', 'users:usr123', {});
    const validation = validateKeyFormat(generated.key);

    expect(validation.valid).toBe(true);
    expect(validation.orgId).toBe('metabob_com');
    expect(validation.userId).toBe('users:usr123');
    expect(validation.keyId).toBe(generated.keyId);
  });

  test('should reject tampered key signature', () => {
    const generated = generateApiKey('metabob_com', 'users:usr123', {});

    // Parse and tamper with signature
    const parts = generated.key.split('-');
    parts[parts.length - 1] = 'tamperedsignature12345678901234';
    const tamperedKey = parts.join('-');

    const validation = validateKeyFormat(tamperedKey);

    expect(validation.valid).toBe(false);
    expect(validation.error).toContain('signature');
  });

  test('should reject tampered payload', () => {
    const generated = generateApiKey('metabob_com', 'users:usr123', {});

    // Parse and tamper with payload
    const parts = generated.key.split('-');
    const encodedPayload = parts[1];
    const signature = parts.slice(2).join('-');

    // Decode, tamper, re-encode
    const payload = Buffer.from(encodedPayload, 'base64url').toString('utf-8');
    const tamperedPayload = payload.replace('metabob_com', 'tampered_org');
    const tamperedEncoded = Buffer.from(tamperedPayload).toString('base64url');

    const tamperedKey = `mb-${tamperedEncoded}-${signature}`;

    const validation = validateKeyFormat(tamperedKey);

    expect(validation.valid).toBe(false);
    expect(validation.error).toContain('signature');
  });

  test('should generate keys with mb prefix only', () => {
    const generated = generateApiKey('metabob_com', 'users:usr123', {});

    // All keys use 'mb' prefix
    expect(generated.prefix).toBe('mb');
    expect(generated.key.startsWith('mb-')).toBe(true);
  });

  test('should handle issuer URL with dashes', () => {
    // Set IDENTITY_ENDPOINT with dashes
    process.env.IDENTITY_ENDPOINT = 'https://identity-test.metabob.com';

    const generated = generateApiKey('testorg', 'users:testuser', {});
    const components = parseApiKey(generated.key);

    expect(components).not.toBeNull();
    expect(components?.iss).toBe('https://identity-test.metabob.com');

    // Cleanup
    delete process.env.IDENTITY_ENDPOINT;
  });

  test('should verify signature correctly', () => {
    const generated = generateApiKey('testorg', 'users:testuser', {});
    const components = parseApiKey(generated.key);

    expect(components).not.toBeNull();
    expect(verifySignature(components!)).toBe(true);
  });

  test('should reject wrong signature in verifySignature', () => {
    const generated = generateApiKey('testorg', 'users:testuser', {});
    const components = parseApiKey(generated.key);

    expect(components).not.toBeNull();

    // Tamper with signature
    components!.signature = 'wrongsignature1234567890123456';

    expect(verifySignature(components!)).toBe(false);
  });
});
