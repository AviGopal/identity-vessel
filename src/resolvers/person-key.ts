/**
 * A PERSON MAKES THEIR OWN KEY. Records takes a row as a person's only for a key identity marks person, and nothing a
 * person could reach marked one: only an admin credential could, through apiKey_write. So a person had no way to have
 * a key whose writes count as theirs. This lets a person signed in on a surface mint one, for themselves:
 *
 *   1. personSession (resolve door, Authorization: ApiKey <the key the person signed in with>): a short-lived token,
 *      typ 'person_session', naming the user, the org and the key it was minted from. Refused for a key whose stored
 *      or derived class is system or peer, a key named as a system key or an admin credential, and a key with the
 *      admin scope: those are the fleet's own and the operator's, never a person's sign-in.
 *   2. personKey_issue (resolve door, Authorization: Bearer <that token>): a NEW key, for the token's user and org,
 *      scopes read and write only, never admin, stamped owner_kind 'person' when its row is created. Returned once;
 *      never logged, never held here. One key per token. No existing row is read for change or changed.
 *
 * Accepted only there: a person_session token is refused at every other door (services/jwt.ts verifyToken,
 * resolvers/auth.ts, services/obo.ts, resolvers/issue-key.ts authorizeAdmin), and every other token (an on-behalf-of
 * token, a general session) is refused here, as is an ApiKey on the mint.
 *
 * RESIDUAL, accepted by the USER: the proof is any signed-in session. An agent holding a key that may sign in on a
 * surface could mint a person key the same way; no check here tells a person from an agent using the surface. The
 * agent side is held by the operator guard, which refuses agent calls to these routes.
 *
 * PERSON_SESSION_SECONDS and PERSON_KEYS_PER_TOKEN are auth limits held as constants, the same law-1 debt as the other
 * credential limits: their home is an owner-role row read at use time.
 */
import { sign, verify } from 'hono/jwt';
import { validateKey } from '../services/validation';
import { isKeyRevoked } from '../db/redis';
import { safeJwtErrorMessage } from '../services/redact';
import { ADMIN_CREDENTIAL_NAMES, SYSTEM_KEY_NAMES } from '../services/owner-kind';
import { persistKey, type IssueKeyResult } from './issue-key';
import { PERSON_SESSION_TYP, isPersonSessionPayload } from '../services/jwt';

export { PERSON_SESSION_TYP, isPersonSessionPayload };

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
const JWT_ISSUER = process.env.JWT_ISSUER || 'https://identity.metabob.com';

export const PERSON_SESSION_SHAPE = 'personSession';
export const PERSON_KEY_SHAPE = 'personKey_issue';
export const PERSON_SESSION_SECONDS = 300;
export const PERSON_KEYS_PER_TOKEN = 1;
export const PERSON_KEY_NAME = 'person-key';

type Refusal = { ok: false; status: number; code: string; message: string };
const no = (status: number, code: string, message: string): Refusal => ({ ok: false, status, code, message });


/** The one-time ids of tokens a key was minted under, until each token expires: so a token mints at most its share. */
const spent = new Map<string, { count: number; exp: number }>();
export function __resetPersonKeyForTests(): void {
  spent.clear();
}

export async function issuePersonSession(authHeader: string | undefined): Promise<{ ok: true; token: string; expires_at: string } | Refusal> {
  if (!authHeader) return no(401, 'MISSING_AUTH_HEADER', 'Missing Authorization header');
  if (!authHeader.startsWith('ApiKey ')) {
    return no(401, 'INVALID_AUTH_SCHEME', 'A person session is minted from the ApiKey the person signed in with');
  }
  const v = await validateKey(authHeader.slice('ApiKey '.length));
  if (!v.valid || !v.orgId || !v.userId || !v.keyId) return no(401, 'INVALID_API_KEY', 'Invalid API key');
  if (await isKeyRevoked(v.keyId)) return no(401, 'REVOKED_API_KEY', 'API key has been revoked');
  if (v.ownerKind === 'system' || v.ownerKind === 'peer') {
    return no(403, 'FORBIDDEN', "a node's own key is not a person's sign-in");
  }
  if (typeof v.name === 'string' && ((SYSTEM_KEY_NAMES as readonly string[]).includes(v.name) || (ADMIN_CREDENTIAL_NAMES as readonly string[]).includes(v.name))) {
    return no(403, 'FORBIDDEN', 'a system or admin credential is not a person\'s sign-in');
  }
  if ((v.scopes ?? []).includes('admin')) return no(403, 'FORBIDDEN', 'an admin key is not a person\'s sign-in');

  const now = Math.floor(Date.now() / 1000);
  const exp = now + PERSON_SESSION_SECONDS;
  const token = await sign({
    iss: JWT_ISSUER,
    sub: v.userId,
    user_id: v.userId,
    org_id: v.orgId,
    typ: PERSON_SESSION_TYP,
    key_id: v.keyId,
    jti: crypto.randomUUID(),
    iat: now,
    exp,
  }, JWT_SECRET, 'HS512');
  return { ok: true, token, expires_at: new Date(exp * 1000).toISOString() };
}

export async function issuePersonKey(authHeader: string | undefined): Promise<IssueKeyResult | Refusal> {
  if (!authHeader) return no(401, 'MISSING_AUTH_HEADER', 'Missing Authorization header');
  if (!authHeader.startsWith('Bearer ')) {
    return no(401, 'INVALID_AUTH_SCHEME', 'A person key is minted only under a person session token');
  }
  let p: Record<string, unknown>;
  try {
    p = await verify(authHeader.slice('Bearer '.length), JWT_SECRET, 'HS512') as Record<string, unknown>;
  } catch (err) {
    return no(401, 'INVALID_JWT', safeJwtErrorMessage(err));
  }
  if (!isPersonSessionPayload(p)) return no(403, 'FORBIDDEN', 'A person key is minted only under a person session token');
  const user = p.user_id, org = p.org_id, jti = p.jti, exp = p.exp;
  if (typeof user !== 'string' || typeof org !== 'string' || typeof jti !== 'string' || typeof exp !== 'number') {
    return no(403, 'FORBIDDEN', 'The person session token names no person');
  }
  const now = Math.floor(Date.now() / 1000);
  for (const [k, s] of spent) if (s.exp <= now) spent.delete(k);
  const used = spent.get(jti)?.count ?? 0;
  if (used >= PERSON_KEYS_PER_TOKEN) return no(429, 'FORBIDDEN', 'This sign-in has already made its key; sign in again to make another');
  spent.set(jti, { count: used + 1, exp });

  const made = await persistKey({ user_id: user, org_id: org, scopes: ['read', 'write'], name: PERSON_KEY_NAME }, 'person');
  if (made.ok) console.log('[PersonKey] a person key was made under a person session'); // never the key or its id
  return made;
}
