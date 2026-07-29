-- identity-vessel — key_session table
--
-- Records every JWT mint that is attributable to an api_key (via
-- /v1/auth/resolve when the impulse pointer type is 'apiKey'). Used by the
-- cloud dashboard to show, per key, session-creation count and estimated
-- active time (sum of exp - iat across rows).
--
-- "Estimated" because we record the JWT lifetime at mint, not actual usage.
-- A key that mints a JWT and never uses it for the next 15 min still
-- contributes 15 min here. The dashboard surfaces this as "estimated".
--
-- Tenant isolation via PERMISSIONS on org_id.

DEFINE TABLE OVERWRITE key_session SCHEMAFULL
  PERMISSIONS
    FOR select WHERE org_id = $auth.org_id OR org_id = $token.org_id
    FOR create, update, delete NONE;  -- writes happen via root-signed connection

DEFINE FIELD OVERWRITE key_id ON key_session TYPE string
  ASSERT $value != NONE;

DEFINE FIELD OVERWRITE org_id ON key_session TYPE string
  ASSERT $value != NONE AND string::starts_with($value, "organizations:");

DEFINE FIELD OVERWRITE user_id ON key_session TYPE option<string>
  ASSERT $value = NONE OR string::starts_with($value, "users:");

DEFINE FIELD OVERWRITE issued_at ON key_session TYPE datetime
  DEFAULT time::now();

DEFINE FIELD OVERWRITE expires_at ON key_session TYPE datetime
  ASSERT $value != NONE;

DEFINE FIELD OVERWRITE source ON key_session TYPE string
  ASSERT $value IN ["resolve_nested", "resolve_flat", "generate"];

DEFINE INDEX OVERWRITE key_session_by_key_issued ON key_session
  FIELDS key_id, issued_at;

DEFINE INDEX OVERWRITE key_session_by_org_issued ON key_session
  FIELDS org_id, issued_at;

DEFINE INDEX OVERWRITE idx_ks_expires ON key_session
  FIELDS expires_at;
