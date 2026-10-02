/**
 * On-behalf-of tokens for federation ingress.
 *
 * WHY THIS EXISTS. A federation transport receives a resolve from another node
 * together with the CALLER's credential. It must not forward that credential to
 * its local vessels (a human's session token handed to another node's vessels
 * could be replayed anywhere that token is accepted), and it must not forward its
 * OWN key either (that is the confused deputy: every remote caller would act with
 * the node's authority). What it forwards instead is this token: identity has
 * validated the caller, and the token names that caller, the node it was minted
 * for, the one shape it may be used for, and a short expiry.
 *
 * What makes it unusable elsewhere:
 *   - `typ: 'obo'` — this service refuses it as the input to another mint (no
 *     re-delegation), as an actor credential, and on every privileged route
 *     (JWT mint, key management, admin). A federation ingress therefore cannot be
 *     handed it as a caller credential at any node.
 *   - `aud` / `obo_shape` — any validator that states the audience it serves
 *     (`X-Auth-Audience: <node>/<shape>` on /v1/auth/resolve) gets a refusal on a
 *     mismatch.
 *   - a TTL of at most MAX_TTL_SECONDS: a vessel validates at request start, so
 *     the token only has to outlive one identity round trip plus clock skew.
 *
 * Deliberately NOT carried: the SurrealDB access claims (AC/NS/DB). An OBO token
 * is not a database credential. /v1/auth/resolve still mints the usual
 * short-lived DB token for a validated OBO caller, scoped to the same audience
 * and expiry, exactly as it does for the caller's own key.
 */
import { sign, verify } from 'hono/jwt';
import { validateKey } from './validation';
import { isKeyRevoked } from '../db/redis';
import { safeJwtErrorMessage } from './redact';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
const JWT_ISSUER = process.env.JWT_ISSUER || 'https://identity.metabob.com';

export const OBO_TYP = 'obo';
export const DEFAULT_TTL_SECONDS = 60;
export const MAX_TTL_SECONDS = 120;

export interface OboAudience {
  node: string;
  shape: string;
}

export interface CallerIdentity {
  org_id: string;
  user_id: string;
  key_id?: string;
  type: 'api_key' | 'session';
  scopes: string[];
}

export type OboFailure = { ok: false; status: number; code: string; message: string };
export type OboSuccess = {
  ok: true;
  token: string;
  expires_at: string;
  caller: CallerIdentity;
  actor: { user_id?: string; key_id?: string };
  audience: OboAudience;
};

const JWT_NS = process.env.JWT_NS || 'activity-system';
const JWT_DB = process.env.JWT_DB || 'learning_loop';

/**
 * The database token /v1/auth/resolve hands back for a validated OBO caller. It keeps
 * the OBO markings (typ, aud, obo_shape, act) and the OBO's own expiry, so the inline
 * mint can never launder a node- and shape-bound grant into a general session.
 */
export async function mintOboDbToken(oboPayload: any): Promise<{ token: string; expires_at: string; issued_at: string }> {
  const payload = { ...oboPayload, AC: 'apikey_token', NS: JWT_NS, DB: JWT_DB };
  return {
    token: await sign(payload, JWT_SECRET, 'HS512'),
    expires_at: new Date(Number(oboPayload.exp) * 1000).toISOString(),
    issued_at: new Date(Number(oboPayload.iat) * 1000).toISOString(),
  };
}

/** True when a decoded JWT payload is an on-behalf-of token. */
export function isOboPayload(payload: unknown): boolean {
  return !!payload && typeof payload === 'object' && (payload as any).typ === OBO_TYP;
}

/**
 * Decode an Authorization-style JWT just far enough to tell whether it is an OBO
 * token. Verification happens elsewhere; this only routes the refusal.
 */
export async function bearerIsObo(token: string): Promise<boolean> {
  try {
    const payload = await verify(token, JWT_SECRET, 'HS512');
    return isOboPayload(payload);
  } catch {
    return false;
  }
}

/** `<node>/<shape>` → audience, or null for anything else. */
export function parseAudienceHeader(v: string | undefined | null): OboAudience | null {
  if (!v) return null;
  const i = v.indexOf('/');
  if (i <= 0 || i === v.length - 1) return null;
  return { node: v.slice(0, i), shape: v.slice(i + 1) };
}

/** True when the OBO payload was minted for exactly this audience. */
export function oboAudienceMatches(payload: any, want: OboAudience): boolean {
  return payload?.aud === `substrate:${want.node}` && payload?.obo_shape === want.shape;
}

const fail = (status: number, code: string, message: string): OboFailure => ({ ok: false, status, code, message });

async function identityOf(header: string, role: 'actor' | 'caller'): Promise<CallerIdentity | OboFailure> {
  const code = role === 'actor' ? 'ACTOR_REJECTED' : 'CALLER_REJECTED';
  const status = role === 'actor' ? 401 : 403;
  if (header.startsWith('ApiKey ')) {
    const v = await validateKey(header.slice('ApiKey '.length));
    if (!v.valid || !v.orgId || !v.userId) return fail(status, code, `${role} credential is not valid`);
    if (v.keyId && (await isKeyRevoked(v.keyId))) return fail(status, code, `${role} credential is revoked`);
    return { org_id: v.orgId, user_id: v.userId, key_id: v.keyId, type: 'api_key', scopes: v.scopes ?? ['read', 'write'] };
  }
  if (header.startsWith('Bearer ')) {
    // An actor is a service: it presents its own key. Accepting a bearer here would
    // let any session holder mint tokens for third parties it has credentials for.
    if (role === 'actor') return fail(status, code, 'the actor must present its own API key');
    let payload: any;
    try {
      payload = await verify(header.slice('Bearer '.length), JWT_SECRET, 'HS512');
    } catch (err) {
      return fail(status, code, `caller token is not valid (${safeJwtErrorMessage(err)})`);
    }
    if (isOboPayload(payload)) {
      // NO RE-DELEGATION. An OBO token presented as a caller credential is exactly the
      // replay this token type exists to prevent: it was minted for one node and one
      // shape, and a second ingress must never turn it into a fresh grant.
      return fail(status, 'OBO_NOT_DELEGABLE', 'an on-behalf-of token cannot be delegated again');
    }
    const user = payload.user_id ?? payload.sub;
    if (!payload.org_id || !user) return fail(status, code, 'caller token carries no identity');
    return { org_id: String(payload.org_id), user_id: String(user), type: 'session', scopes: ['read', 'write'] };
  }
  return fail(status, code, `${role} credential must use the ApiKey or Bearer scheme`);
}

/**
 * Validate the caller credential presented to a federation ingress and mint a
 * token the ingress can hand to ONE local vessel for ONE shape.
 *
 * @param actorHeader the ingress's own Authorization header (its API key)
 * @param callerHeader the caller's credential as carried across the overlay,
 *        in Authorization form ("ApiKey …" or "Bearer …")
 */
export async function mintOnBehalfOf(
  actorHeader: string | undefined,
  callerHeader: unknown,
  audience: unknown,
  ttlSeconds?: unknown,
): Promise<OboSuccess | OboFailure> {
  if (!actorHeader) return fail(401, 'MISSING_AUTH_HEADER', 'the ingress must authenticate with its own API key');
  const actor = await identityOf(actorHeader, 'actor');
  if ('ok' in actor) return actor;

  const a = audience as Partial<OboAudience> | undefined;
  if (!a || typeof a.node !== 'string' || !a.node || typeof a.shape !== 'string' || !a.shape) {
    return fail(400, 'INVALID_AUDIENCE', 'audience must name the node and the shape');
  }
  if (typeof callerHeader !== 'string' || !callerHeader) {
    return fail(403, 'CALLER_REJECTED', 'no caller credential was presented');
  }
  const caller = await identityOf(callerHeader, 'caller');
  if ('ok' in caller) return caller;

  const ttl = Math.max(1, Math.min(MAX_TTL_SECONDS, Number(ttlSeconds) > 0 ? Number(ttlSeconds) : DEFAULT_TTL_SECONDS));
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: JWT_ISSUER,
    sub: caller.user_id,
    iat: now,
    exp: now + ttl,
    typ: OBO_TYP,
    aud: `substrate:${a.node}`,
    obo_shape: a.shape,
    org_id: caller.org_id,
    user_id: caller.user_id,
    // Never more than member, never admin scope: an ingress grant is a resolve, not
    // an administrative act, whatever the caller could do at home.
    role: 'member',
    scopes: caller.scopes.filter((s) => s !== 'admin'),
    project_ids: [] as string[],
    caller_key_id: caller.key_id,
    caller_type: caller.type,
    act: { sub: actor.user_id, key_id: actor.key_id },
  };
  const token = await sign(payload, JWT_SECRET, 'HS512');
  return {
    ok: true,
    token,
    expires_at: new Date((now + ttl) * 1000).toISOString(),
    caller,
    actor: { user_id: actor.user_id, key_id: actor.key_id },
    audience: { node: a.node, shape: a.shape },
  };
}
