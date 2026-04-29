-- identity-vessel — api_key ownership migration
--
-- Takes ownership of the api_key schema from metabob-activity-api/sql/schemas/
-- 049-api-key-direct-auth.surql per the architectural realignment. Idempotent
-- via DEFINE … OVERWRITE; safe to re-run on the deployed canary table.
--
-- TABLE NAME: `api_key` (singular). The plural `api_keys` was a stray declared
-- by user-vessel that never matched runtime usage; activity-api created and
-- the runtime auth path uses `api_key` (singular).
--
-- Identity-vessel owns: table, PERMISSIONS, key_hash, org_id, user_id, scopes
-- (+ scopes.*), name, created_at, expires_at, last_used_at, is_active, key_id,
-- key_prefix, and indices including the F-NN-I lookup index on key_id.
--
-- F-NN-H: org_id and user_id are TYPE string holding record-reference-as-string
-- (e.g., "organizations:metabob", "users:abc"). Matches the deployed canary
-- schema for `api_key` (singular).

DEFINE TABLE OVERWRITE api_key SCHEMAFULL
  PERMISSIONS
    -- Tenant-scoped read; honors both $auth (JWT) and $token (API-key) paths.
    FOR select WHERE org_id = $auth.org_id OR org_id = $token.org_id
    -- Mutations: admin/owner role OR the key's owning user, within org.
    FOR create, update, delete WHERE
      (org_id = $auth.org_id OR org_id = $token.org_id)
      AND (
        $auth.role = 'admin'
        OR $auth.role = 'owner'
        OR $token.role = 'admin'
        OR $token.role = 'owner'
        OR user_id = $auth.user_id
        OR user_id = $token.user_id
      );

DEFINE FIELD OVERWRITE key_hash ON api_key TYPE string
  ASSERT $value != NONE;

DEFINE FIELD OVERWRITE org_id ON api_key TYPE string
  ASSERT $value != NONE AND string::starts_with($value, "organizations:");

DEFINE FIELD OVERWRITE user_id ON api_key TYPE option<string>
  ASSERT $value = NONE OR string::starts_with($value, "users:");

DEFINE FIELD OVERWRITE scopes ON api_key TYPE array<string> DEFAULT [];
DEFINE FIELD OVERWRITE scopes.* ON api_key TYPE string;

DEFINE FIELD OVERWRITE name ON api_key TYPE option<string>;

DEFINE FIELD OVERWRITE created_at ON api_key TYPE datetime
  DEFAULT time::now();
DEFINE FIELD OVERWRITE updated_at ON api_key TYPE datetime
  DEFAULT time::now();
DEFINE FIELD OVERWRITE expires_at ON api_key TYPE option<datetime>;
DEFINE FIELD OVERWRITE last_used_at ON api_key TYPE option<datetime>;
DEFINE FIELD OVERWRITE is_active ON api_key TYPE bool DEFAULT true;

-- key_id: HMAC-embedded keyId from the canonical mb-<base64>-<hmac> payload.
-- Used by validation.ts:lookupKeyScopes to find the row when the SurrealDB
-- record id wasn't pre-set to match.
DEFINE FIELD OVERWRITE key_id ON api_key TYPE option<string>;

-- key_prefix: human/admin-friendly handle for the key (e.g., "key_avi_canary_admin01").
-- Independent of key_id; allows ops scripts to look up by stable label.
DEFINE FIELD OVERWRITE key_prefix ON api_key TYPE option<string>;

DEFINE INDEX OVERWRITE idx_api_key_hash ON api_key FIELDS key_hash UNIQUE;
DEFINE INDEX OVERWRITE idx_api_key_org ON api_key FIELDS org_id;
DEFINE INDEX OVERWRITE idx_api_key_user ON api_key FIELDS user_id;
DEFINE INDEX OVERWRITE idx_api_key_key_id ON api_key FIELDS key_id;
DEFINE INDEX OVERWRITE idx_api_key_key_prefix ON api_key FIELDS key_prefix;
