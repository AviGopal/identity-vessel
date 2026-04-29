-- identity-vessel — api_keys ownership migration
--
-- Takes ownership of the api_keys schema from metabob-activity-api/sql/schemas/
-- 049-api-key-direct-auth.surql per the architectural realignment. Idempotent
-- via DEFINE … OVERWRITE; safe to re-run on the deployed canary table.
--
-- Identity-vessel owns: table, PERMISSIONS, key_hash, org_id, user_id, scopes
-- (+ scopes.*), created_at, expires_at, last_used_at, is_active, and the three
-- core indices.
--
-- user-vessel owns (in user-vessel/sql/004-api-keys-scopes-and-key-id.surql):
-- the optional key_id field + idx_api_keys_key_id index. NOT redefined here.
--
-- org_id and user_id are typed as record<organizations> / record<users> to
-- match the deployed canary schema (which differs from user-vessel's own
-- api_keys variant in 001-init-schema.surql that uses TYPE string).
-- Reconciliation is out of scope; canary is the source of truth.

DEFINE TABLE OVERWRITE api_keys SCHEMAFULL
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

DEFINE FIELD OVERWRITE key_hash ON api_keys TYPE string
  ASSERT $value != NONE;

DEFINE FIELD OVERWRITE org_id ON api_keys TYPE record<organizations>
  VALUE $value OR $auth.org_id
  ASSERT $value != NONE;

DEFINE FIELD OVERWRITE user_id ON api_keys TYPE record<users>
  VALUE $value
  ASSERT $value != NONE;

DEFINE FIELD OVERWRITE scopes ON api_keys TYPE array<string> DEFAULT [];
DEFINE FIELD OVERWRITE scopes.* ON api_keys TYPE string;

DEFINE FIELD OVERWRITE created_at ON api_keys TYPE datetime
  DEFAULT time::now();
DEFINE FIELD OVERWRITE expires_at ON api_keys TYPE option<datetime>;
DEFINE FIELD OVERWRITE last_used_at ON api_keys TYPE option<datetime>;
DEFINE FIELD OVERWRITE is_active ON api_keys TYPE bool DEFAULT true;

DEFINE INDEX OVERWRITE idx_api_key_hash ON api_keys FIELDS key_hash UNIQUE;
DEFINE INDEX OVERWRITE idx_api_key_org ON api_keys FIELDS org_id;
DEFINE INDEX OVERWRITE idx_api_key_user ON api_keys FIELDS user_id;
