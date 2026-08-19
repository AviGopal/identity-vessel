/**
 * Credential redaction helpers.
 *
 * Rule: a presented credential (API key, bearer token, password) must NEVER
 * appear in a response body, a thrown error, or a log line. Error strings
 * propagate into operator logs, agent transcripts and screen recordings, and
 * an echoed credential there is a live credential in someone else's hands.
 *
 * Two vectors are covered here:
 *
 *  1. Library error messages. hono's JWT verifier interpolates the whole token
 *     into its exception message (`invalid JWT token: <token>`, and the same
 *     for not-before / expired / signature-mismatched). Passing `err.message`
 *     through — as verifyToken() used to — put the caller's bearer token in a
 *     401 body. safeJwtErrorMessage() maps the error CLASS to a fixed string
 *     and never reads `.message`, so a hono upgrade that adds a new
 *     token-bearing class still cannot leak.
 *
 *  2. Downstream echoes. When this vessel forwards a credential to another
 *     service (C6 issuer delegation, user-vessel account lookup) and that
 *     service is itself vulnerable, its error string can carry our credential
 *     back. redactCredential() scrubs those strings before we surface or log
 *     them.
 *
 * Diagnostics are preserved: the FAILURE REASON survives (malformed vs expired
 * vs bad signature), only the secret material is removed.
 */

/** Placeholder substituted for any redacted secret material. */
const REDACTED = '[redacted]';

// Metabob API keys are `mb-<base64url payload>-<signature>`.
const API_KEY_SHAPE = /mb-[A-Za-z0-9_\-=]{8,}/g;
// Compact JWS: three base64url segments, header always starts `eyJ`.
const JWT_SHAPE = /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Remove credential material from a free-text message.
 *
 * Any credential passed in `credentials` is removed by exact substring match
 * (with or without an `ApiKey `/`Bearer ` prefix, since we sometimes hold the
 * whole header). Key-shaped and JWT-shaped substrings are then removed
 * generically, which covers the case where a downstream service echoes a
 * credential we did not pass in verbatim.
 */
export function redactCredential(
  text: string,
  ...credentials: Array<string | undefined | null>
): string {
  let out = text;

  for (const raw of credentials) {
    if (!raw) continue;
    const bare = raw.replace(/^(ApiKey|Bearer)\s+/i, '').trim();
    for (const needle of new Set([raw, bare])) {
      // A 1-2 char "credential" would scrub the whole message; ignore those.
      if (needle.length < 8) continue;
      out = out.replace(new RegExp(escapeRegExp(needle), 'g'), REDACTED);
    }
  }

  return out.replace(API_KEY_SHAPE, REDACTED).replace(JWT_SHAPE, REDACTED);
}

/**
 * Non-reversible hint for an operator correlating a failure to a credential.
 * Last 4 characters only, and only when there is enough material that the
 * hint is not the credential.
 */
export function credentialHint(credential: string | undefined | null): string {
  if (!credential || credential.length < 12) return 'unknown';
  return `…${credential.slice(-4)}`;
}

/**
 * hono JWT error class name -> safe, credential-free message.
 * Keys are the `name` values set by hono/utils/jwt/types.
 */
const SAFE_JWT_ERROR_BY_NAME: Record<string, string> = {
  JwtTokenInvalid: 'JWT is malformed',
  JwtTokenNotBefore: 'JWT is not valid yet',
  JwtTokenExpired: 'JWT has expired',
  JwtTokenIssuedAt: 'JWT has an invalid "iat" claim',
  JwtTokenIssuer: 'JWT issuer is not accepted',
  JwtTokenAudience: 'JWT audience is not accepted',
  JwtTokenSignatureMismatched: 'JWT signature verification failed',
  JwtHeaderInvalid: 'JWT header is invalid',
  JwtHeaderRequiresKid: 'JWT header is missing "kid"',
  JwtPayloadRequiresAud: 'JWT payload is missing "aud"',
  JwtAlgorithmMismatch: 'JWT algorithm mismatch',
  JwtAlgorithmRequired: 'JWT algorithm was not specified',
  JwtAlgorithmNotAllowed: 'JWT algorithm is not allowed',
  JwtAlgorithmNotImplemented: 'JWT algorithm is not implemented',
  JwtSymmetricAlgorithmNotAllowed: 'JWT algorithm is not allowed',
};

/**
 * Map a JWT verification failure to a message that is safe to return and log.
 *
 * Deliberately fails CLOSED: an unrecognised error class yields the generic
 * message rather than its own `.message`, because several hono JWT error
 * classes embed the token (or its decoded header/payload) in that string and a
 * future version may add more.
 */
export function safeJwtErrorMessage(error: unknown): string {
  const name = error instanceof Error ? error.name : undefined;
  return (name && SAFE_JWT_ERROR_BY_NAME[name]) || 'Token verification failed';
}
