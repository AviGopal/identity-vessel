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
    const url = `${this.endpoint}/mcp/tools/call`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

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
        return null;
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
        return null;
      }

      const accounts = Array.isArray(body.result.accounts) ? body.result.accounts : [];
      return accounts;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'unknown error';
      console.warn('[UserVesselClient] user-vessel unreachable', { url, err: message });
      return null;
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
