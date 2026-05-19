/**
 * User-vessel HTTP client (read-only).
 *
 * Identity-vessel calls user-vessel's MCP `query-user-context(user_id)` tool
 * at auth-resolve time so we can emit an `account_id` claim alongside the
 * legacy `org_id` claim. user-vessel is the source of truth for the
 * user→account mapping; identity-vessel does not maintain its own cache.
 *
 * Auth strategy:
 *   The caller's own Authorization header is forwarded back to user-vessel.
 *   This avoids identity-vessel needing a system credential and naturally
 *   scopes the lookup to the caller's own user record.  user-vessel's
 *   `requireAuth` middleware will round-trip back to identity-vessel
 *   `/v1/auth/resolve` to validate that header — that lookup terminates
 *   without further delegation, so there is no infinite loop.
 *
 * Graceful degradation:
 *   Any non-2xx response, network error, or unexpected payload returns
 *   `null` and emits a single warn log.  Callers MUST treat `null` as
 *   "account_id unknown" and continue without it; downstream tenant helpers
 *   in user-vessel/activity-api fall back to deriving from `org_id`.
 */

const DEFAULT_TIMEOUT_MS = 1000;

/**
 * TTL cache for user-account lookups.
 *
 * Audit 2026-05-16: enrichWithAccountId was hitting user-vessel on EVERY
 * /v1/auth/resolve call — multiplying load on user-vessel (whose own
 * /v1/auth/resolve round-trip back to identity-vessel further amplified
 * the cascade) and adding ~1s timeout latency when user-vessel was slow.
 * A per-user 5-minute TTL collapses repeated lookups to one network call
 * per user per window.
 *
 * Cache invalidation trade-off: account-membership changes (user added to /
 * removed from an account) take up to TTL_MS to propagate to /v1/auth/resolve
 * responses. This is acceptable because tenant helpers in downstream services
 * fall back to deriving accountId from orgId when missing, so a stale-cached
 * accountId can only cause incorrect default-account selection, not
 * authorization bypass. Out-of-scope to add explicit invalidation here.
 */
const USER_ACCOUNTS_CACHE_TTL_MS = Number(
  process.env.IDENTITY_USER_ACCOUNTS_CACHE_TTL_MS || 5 * 60 * 1000,
);

const SWEEP_THRESHOLD = 1024;

interface CacheEntry {
  result: AccountMembership[] | null;
  expires: number;
}

const userAccountsCache: Map<string, CacheEntry> = new Map();

function sweepExpired(now: number): void {
  for (const [k, v] of userAccountsCache.entries()) {
    if (v.expires <= now) userAccountsCache.delete(k);
  }
}

/** Test-only: clear all cached user-account entries. */
export function _resetUserAccountsCache(): void {
  userAccountsCache.clear();
}

export interface AccountMembership {
  account_id: string;
  role: string;
  joined_at: string;
}

export interface UserVesselClientOptions {
  endpoint: string;
  /** Optional fetch override for tests. Defaults to globalThis.fetch. */
  fetchImpl?: typeof fetch;
  /** Per-call timeout in ms.  Default 1000ms. */
  timeoutMs?: number;
}

export class UserVesselClient {
  private readonly endpoint: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(options: UserVesselClientOptions) {
    this.endpoint = options.endpoint.replace(/\/+$/, '');
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  /**
   * Look up the caller's account memberships by user_id.
   *
   * Returns null on any failure (network, timeout, non-2xx, malformed response).
   */
  async queryUserAccounts(
    userId: string,
    authHeader: string,
  ): Promise<AccountMembership[] | null> {
    // Cache hot-path. We cache by userId only (not authHeader): the lookup is
    // user-vessel's own user→account mapping, which does not vary by the
    // calling credential — user-vessel just needs *any* valid credential to
    // authorize the read, and we forward the caller's header to satisfy that.
    const now = Date.now();
    const cached = userAccountsCache.get(userId);
    if (cached && cached.expires > now) {
      console.info('[UserVesselClient] cache hit', { user_id: userId });
      return cached.result;
    }

    // Opportunistic sweep when the map grows large (audit 2026-05-16 fix).
    if (userAccountsCache.size >= SWEEP_THRESHOLD) {
      sweepExpired(now);
    }

    const url = `${this.endpoint}/mcp/tools/call`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    // Cache BOTH success and null results — null indicates user-vessel was
    // unreachable or returned a non-success body, and the calling auth-resolver
    // already treats null as "accountId unknown, derive from orgId". Caching
    // null prevents a brief user-vessel outage from causing identity-vessel
    // to retry on every auth request for the next 5 minutes.
    const cacheAndReturn = (result: AccountMembership[] | null): AccountMembership[] | null => {
      userAccountsCache.set(userId, {
        result,
        expires: Date.now() + USER_ACCOUNTS_CACHE_TTL_MS,
      });
      return result;
    };

    try {
      const response = await this.fetchImpl(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: authHeader,
        },
        body: JSON.stringify({
          name: 'query-user-context',
          arguments: { user_id: userId },
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        console.warn('[UserVesselClient] non-2xx from user-vessel', {
          url,
          status: response.status,
        });
        return cacheAndReturn(null);
      }

      const body = (await response.json()) as {
        ok?: boolean;
        result?: { accounts?: AccountMembership[] };
        error?: string;
      };

      if (!body.ok || !body.result) {
        console.warn('[UserVesselClient] user-vessel returned ok=false', {
          error: body.error,
        });
        return cacheAndReturn(null);
      }

      const accounts = Array.isArray(body.result.accounts) ? body.result.accounts : [];
      return cacheAndReturn(accounts);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'unknown error';
      console.warn('[UserVesselClient] user-vessel unreachable', { url, err: message });
      return cacheAndReturn(null);
    } finally {
      clearTimeout(timer);
    }
  }
}

/**
 * Pick the user's "default" account from a membership list.
 *
 * Phase A semantics — there is no explicit `default_account_id` field in
 * user-vessel yet (the openspec change reserves that work).  Selection order:
 *   1. The first owner-role account (highest authority)
 *   2. The first member-role account
 *   3. The first account in the list (any role)
 *
 * Returns null if the membership list is empty.
 */
export function pickDefaultAccount(
  memberships: AccountMembership[],
): AccountMembership | null {
  if (memberships.length === 0) return null;

  // Prefer owner role.
  const owner = memberships.find((m) => m.role === 'owner');
  if (owner) return owner;

  // Then member role.
  const member = memberships.find((m) => m.role === 'member');
  if (member) return member;

  // Fallback: first entry regardless of role.
  return memberships[0];
}

/**
 * Normalize a raw account_id (e.g. "metabob") to the canonical
 * "accounts:<slug>" form expected by activity-api/user-vessel PERMISSIONS
 * clauses.  Already-prefixed values pass through unchanged.
 */
export function normalizeAccountId(raw: string): string {
  if (raw.startsWith('accounts:')) return raw;
  if (raw.startsWith('organizations:')) {
    return `accounts:${raw.slice('organizations:'.length)}`;
  }
  return `accounts:${raw}`;
}
