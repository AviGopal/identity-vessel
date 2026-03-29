/**
 * Tests for API key validation
 */

import { test, expect, describe } from 'bun:test';
import { parseApiKey, validateKeyFormat } from './validation';
import { generateApiKey } from './keyGeneration';

describe('API Key Validation', () => {
  test('should parse valid base64-encoded API key format', () => {
    // Encode a valid key: mb_live-metabob_com-usr_123-key_abc123-a1b2c3d4
    const rawKey = 'mb_live-metabob_com-usr_123-key_abc123-a1b2c3d4';
    const key = Buffer.from(rawKey).toString('base64url');
    const result = parseApiKey(key);

    expect(result).not.toBeNull();
    expect(result?.prefix).toBe('mb_live');
    expect(result?.orgId).toBe('metabob_com');
    expect(result?.userId).toBe('usr_123');
    expect(result?.keyId).toBe('key_abc123');
  });

  test('should reject invalid base64', () => {
    const key = 'not-valid-base64!!!';
    const result = parseApiKey(key);

    expect(result).toBeNull();
  });

  test('should reject malformed decoded key', () => {
    const rawKey = 'mb_live-incomplete';
    const key = Buffer.from(rawKey).toString('base64url');
    const result = parseApiKey(key);

    expect(result).toBeNull();
  });

  test('should validate generated key successfully', () => {
    const generated = generateApiKey('metabob_com', 'usr_123', {});
    const validation = validateKeyFormat(generated.key);

    expect(validation.valid).toBe(true);
    expect(validation.orgId).toBe('metabob_com');
    expect(validation.userId).toBe('usr_123');
    expect(validation.keyId).toBe(generated.keyId);
  });

  test('should reject tampered key signature', () => {
    const generated = generateApiKey('metabob_com', 'usr_123', {});

    // Decode, tamper with the signature, re-encode
    const decoded = Buffer.from(generated.key, 'base64url').toString('utf-8');
    const parts = decoded.split('-');
    parts[parts.length - 1] = 'tampered123';
    const tamperedRaw = parts.join('-');
    const tamperedKey = Buffer.from(tamperedRaw).toString('base64url');

    const validation = validateKeyFormat(tamperedKey);

    expect(validation.valid).toBe(false);
    expect(validation.error).toContain('Invalid');
  });

  test('should generate test keys in non-production', () => {
    const generated = generateApiKey('metabob_com', 'usr_123', {});

    // In test environment, should use mb_test prefix
    expect(generated.prefix).toBe('mb_test');

    // Decode and verify prefix
    const decoded = Buffer.from(generated.key, 'base64url').toString('utf-8');
    expect(decoded.startsWith('mb_test-')).toBe(true);
  });
});
