-- =============================================================================
-- Identity Vessel: Authentication Tables
-- =============================================================================

-- =============================================================================
-- Table: organizations
-- =============================================================================

DEFINE TABLE IF NOT EXISTS organizations SCHEMAFULL;

DEFINE FIELD IF NOT EXISTS name ON organizations TYPE string
  ASSERT $value != NONE;

DEFINE FIELD IF NOT EXISTS created_at ON organizations TYPE datetime
  VALUE $value OR time::now();

DEFINE FIELD IF NOT EXISTS updated_at ON organizations TYPE datetime
  VALUE $value OR time::now();

-- =============================================================================
-- Table: users
-- =============================================================================

DEFINE TABLE IF NOT EXISTS users SCHEMAFULL;

DEFINE FIELD IF NOT EXISTS email ON users TYPE string
  ASSERT $value != NONE;

DEFINE FIELD IF NOT EXISTS name ON users TYPE option<string>;

DEFINE FIELD IF NOT EXISTS org_id ON users TYPE string
  ASSERT $value != NONE
  COMMENT "Organization ID (string reference, not RECORD)";

DEFINE FIELD IF NOT EXISTS password_hash ON users TYPE option<string>
  COMMENT "Argon2 hash of password (optional for OAuth users)";

DEFINE FIELD IF NOT EXISTS created_at ON users TYPE datetime
  VALUE $value OR time::now();

DEFINE FIELD IF NOT EXISTS updated_at ON users TYPE datetime
  VALUE $value OR time::now();

-- Unique constraint on email
DEFINE INDEX IF NOT EXISTS idx_users_email
  ON users FIELDS email UNIQUE;

-- =============================================================================
-- Table: api_keys (metadata for HMAC-based keys)
-- =============================================================================

DEFINE TABLE IF NOT EXISTS api_keys SCHEMAFULL;

DEFINE FIELD IF NOT EXISTS key_id ON api_keys TYPE string
  ASSERT $value != NONE
  COMMENT "Unique key identifier (embedded in HMAC key)";

DEFINE FIELD IF NOT EXISTS org_id ON api_keys TYPE string
  ASSERT $value != NONE;

DEFINE FIELD IF NOT EXISTS user_id ON api_keys TYPE string
  ASSERT $value != NONE;

DEFINE FIELD IF NOT EXISTS name ON api_keys TYPE option<string>
  COMMENT "User-provided key name";

DEFINE FIELD IF NOT EXISTS scopes ON api_keys TYPE array
  DEFAULT ["read", "write"];

DEFINE FIELD IF NOT EXISTS revoked ON api_keys TYPE bool
  DEFAULT false;

DEFINE FIELD IF NOT EXISTS created_at ON api_keys TYPE datetime
  VALUE $value OR time::now();

DEFINE FIELD IF NOT EXISTS last_used_at ON api_keys TYPE option<datetime>;

-- Unique constraint on key_id
DEFINE INDEX IF NOT EXISTS idx_api_keys_key_id
  ON api_keys FIELDS key_id UNIQUE;

-- Index for revocation lookups
DEFINE INDEX IF NOT EXISTS idx_api_keys_revoked
  ON api_keys FIELDS revoked, key_id;
