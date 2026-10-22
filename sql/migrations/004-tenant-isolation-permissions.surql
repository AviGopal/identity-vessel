-- =============================================================================
-- 004 — tenant-isolation PERMISSIONS for the identity/auth tables
--
-- CLOSES a latent cross-tenant isolation hole: users / organizations /
-- organization_members were live as `TYPE ANY SCHEMALESS PERMISSIONS NONE`
-- (created implicitly via INSERT — identity-vessel's migrations were not applied
-- on the substrate and user-vessel, the nominal schema owner, is not deployed).
-- One tenant is seeded today and every vessel connects as SurrealDB ROOT
-- (which bypasses record PERMISSIONS), so this is LATENT, not a live leak —
-- it becomes a real cross-tenant leak the moment a 2nd org is provisioned while
-- any $token/JWT-scoped path reaches these tables. These clauses mirror the
-- pattern already carried by the `impulse` table.
--
-- SCHEMALESS-preserving + PERMISSIONS-only ON PURPOSE: applying user-vessel's
-- full SCHEMAFULL field list would REJECT any field identity-vessel writes that
-- is not in that list (the two vessels' write shapes are not co-verified). These
-- statements add tenant isolation without changing schema strictness, so
-- identity-vessel's existing inserts keep working.
--
-- OVERWRITE (not IF NOT EXISTS): the tables already exist (implicit-INSERT
-- creation). OVERWRITE replaces only the table DEFINITION; row data is preserved
-- (verified on-box 2026-07-23: 1 row each survived the OVERWRITE, root reads
-- unaffected — the login-path `SELECT ... FROM users WHERE email = $email` runs
-- as root and so bypasses these select PERMISSIONS, i.e. login cannot break).
--
-- Applied by identity-vessel on unit start like every file in this directory
-- (src/db/migrations.ts), recorded in init_migrations, so a fresh deploy gets
-- it too. It was first applied by hand to a running database on 2026-07-23.
-- Every statement is DEFINE TABLE ... OVERWRITE and nothing here writes a row:
-- re-applying it resets the three table definitions to these and leaves their
-- rows as they are.
-- =============================================================================

-- organizations: an org is visible to a token scoped to that org.
DEFINE TABLE OVERWRITE organizations TYPE ANY SCHEMALESS
  PERMISSIONS
    FOR select
      WHERE $token.org_id = string::concat("organizations:", meta::id(id))
         OR $token.org_id = type::string(id)
    FOR create
      WHERE $token.role IN ["owner", "admin"] OR $token = NONE
    FOR update
      WHERE ($token.org_id = string::concat("organizations:", meta::id(id))
             OR $token.org_id = type::string(id))
        AND $token.role IN ["owner", "admin"]
    FOR delete
      WHERE ($token.org_id = string::concat("organizations:", meta::id(id))
             OR $token.org_id = type::string(id))
        AND $token.role = "owner";

-- users: a user reads their own record, or same-org users (default_org_id match).
DEFINE TABLE OVERWRITE users TYPE ANY SCHEMALESS
  PERMISSIONS
    FOR select WHERE $token.user_id = type::string(id) OR $token.org_id = default_org_id
    FOR create WHERE $token != NONE
    FOR update WHERE $token.user_id = type::string(id)
    FOR delete WHERE $token.role = "owner";

-- organization_members: membership rows are visible to tokens scoped to that org.
DEFINE TABLE OVERWRITE organization_members TYPE ANY SCHEMALESS
  PERMISSIONS
    FOR select WHERE $token.org_id = org_id
    FOR create, update WHERE $token.org_id = org_id AND $token.role IN ["owner", "admin"]
    FOR delete WHERE $token.org_id = org_id AND $token.role = "owner";
