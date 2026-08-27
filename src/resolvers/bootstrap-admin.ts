/**
 * Loopback admin bootstrap — recover key management on a substrate that holds no
 * admin plaintext.
 *
 * WHY THIS EXISTS
 * ---------------
 * SUBSTRATE_ADMIN_KEY is the credential /v1/jwt/generate's role gate (SEC-5,
 * a9db360) requires before it will mint the admin JWT that every operator
 * /v1/keys/* command presents. Historically it was written by exactly ONE code
 * path — seed-identity.ts's genuine-first-boot branch — while /v1/keys/issue,
 * the supported way to mint an admin key, returns the plaintext once over HTTP
 * and persists only a SHA-256 hash.
 *
 * So a substrate could hold an ACTIVE admin key it was unable to use. Measured on
 * a hub 2026-08-26: `substrate-admin` (read,write,admin) minted 2026-07-16 —
 * fifteen days after that substrate's first boot, so not by the seeder — with
 * SUBSTRATE_ADMIN_KEY empty in both /etc/substrate/env and .substrate-secrets.
 * Once SEC-5 landed, issue/list/revoke all returned "requires admin entitlement",
 * and the only credential that could mint a replacement was the missing one.
 * There was no way back short of hand-editing the datastore.
 *
 * WHY THIS IS NOT A BACKDOOR
 * --------------------------
 * Two gates, neither satisfiable from off-box:
 *
 *   1. The request must arrive on LOOPBACK, judged by the real socket peer via
 *      getConnInfo(). The x-forwarded-for header is deliberately NOT consulted —
 *      it is attacker-controlled, and identity-vessel is published on a host port
 *      in hub deployments, so a header-based check would be no check at all.
 *   2. The caller must present API_KEY_SECRET, which lives in /etc/substrate/env
 *      (root-only, mode 0600) inside the container.
 *
 * Anyone who satisfies both already owns the box and could write the api_key
 * table directly. This endpoint therefore grants no capability its caller lacks;
 * it routes an authority that already exists through an audited, logged path
 * instead of a hand-forged admin JWT.
 *
 * WHAT IT DELIBERATELY DOES NOT DO
 * --------------------------------
 * It does not refuse when an admin key already exists, and it never revokes one.
 * An orphaned admin row whose plaintext was lost is indistinguishable from one an
 * operator still holds. Gating on "no admin key exists" would refuse in exactly
 * the state this exists to repair, and revoking to make room could cut off a live
 * operator. Mints are additive; multiple admin keys coexist harmlessly.
 */

import type { Context } from 'hono';
import { getConnInfo } from 'hono/bun';
import { timingSafeEqual } from 'crypto';
import { validateKey } from '../services/validation';
import { isKeyRevoked } from '../db/redis';
import { mintApiKey } from './issue-key';

// ::ffff:127.0.0.1 is how a v4 loopback peer presents on a dual-stack listener.
const LOOPBACK_PEERS = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);

/**
 * Constant-time string compare. timingSafeEqual throws on length mismatch, and
 * letting that throw would leak the expected length through the exception path,
 * so unequal lengths return false directly and the timing-safe compare only ever
 * runs on equal-length buffers.
 */
function constantTimeEquals(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

export interface BootstrapResult {
  status: number;
  body: Record<string, unknown>;
}

function refuse(status: number, code: string, message: string, gate: string): BootstrapResult {
  // Every refusal names the gate that produced it: the failure mode this repairs
  // was invisible precisely because nothing logged why a credential path closed.
  console.warn(`[BootstrapAdmin] REFUSED at gate '${gate}': ${code}`);
  return { status, body: { success: false, error: { code, message } } };
}

export async function bootstrapAdminKey(c: Context): Promise<BootstrapResult> {
  // ── Gate 1: loopback, by socket peer ──────────────────────────────────────
  // Fails CLOSED when the peer cannot be determined. An origin we cannot name
  // must never be treated as local.
  let peer: string | undefined;
  try {
    peer = getConnInfo(c).remote.address;
  } catch {
    peer = undefined;
  }
  if (!peer || !LOOPBACK_PEERS.has(peer)) {
    return refuse(
      403,
      'BOOTSTRAP_NOT_LOCAL',
      'This endpoint is reachable only from inside the substrate container',
      `loopback (peer=${peer ?? 'unknown'})`,
    );
  }

  // ── Gate 2: caller binding ────────────────────────────────────────────────
  // The minted key is issued for the org/user of a credential the caller already
  // holds, so this cannot mint into another tenant. Admin scope is NOT required —
  // that is the entire point.
  const authHeader = c.req.header('Authorization');
  if (!authHeader?.startsWith('ApiKey ')) {
    return refuse(401, 'MISSING_AUTH', 'Authorization: ApiKey <key> required', 'caller-binding');
  }
  const validation = await validateKey(authHeader.slice('ApiKey '.length));
  if (!validation.valid || !validation.orgId || !validation.userId) {
    return refuse(401, 'INVALID_API_KEY', validation.error || 'Invalid API key', 'caller-binding');
  }
  if (validation.keyId && (await isKeyRevoked(validation.keyId))) {
    return refuse(401, 'REVOKED_API_KEY', 'API key has been revoked', 'caller-binding');
  }

  // ── Gate 3: proof of in-container root ────────────────────────────────────
  const secret = process.env.API_KEY_SECRET || '';
  if (!secret) {
    return refuse(500, 'BOOTSTRAP_UNAVAILABLE', 'API_KEY_SECRET is not configured', 'secret-proof');
  }
  let body: any = {};
  try {
    body = await c.req.json();
  } catch {
    body = {};
  }
  const presentedSecret = typeof body?.bootstrap_secret === 'string' ? body.bootstrap_secret : '';
  if (!presentedSecret || !constantTimeEquals(presentedSecret, secret)) {
    return refuse(403, 'BOOTSTRAP_BAD_SECRET', 'bootstrap_secret does not match', 'secret-proof');
  }

  const name =
    typeof body?.name === 'string' && body.name.length > 0 ? body.name : 'substrate-admin';

  const result = await mintApiKey({
    user_id: validation.userId,
    org_id: validation.orgId,
    scopes: ['read', 'write', 'admin'],
    name,
  });

  if (!result.ok) {
    console.error(`[BootstrapAdmin] mint FAILED: ${result.code} ${result.message}`);
    return {
      status: result.status,
      body: { success: false, error: { code: result.code, message: result.message } },
    };
  }

  // Audit loudly. This is a privileged mint; the trail must survive in the
  // journal. The key itself is never logged.
  console.warn(
    `[BootstrapAdmin] GRANTED admin key key_id=${result.key_id} org=${validation.orgId} ` +
      `user=${validation.userId} name=${name} peer=${peer}`,
  );

  return {
    status: 200,
    body: {
      success: true,
      data: { key: result.key, key_id: result.key_id, expires_at: result.expires_at },
    },
  };
}
