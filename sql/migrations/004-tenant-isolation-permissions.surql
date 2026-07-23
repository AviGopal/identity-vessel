-- =============================================================================
-- 004 — tenant-isolation PERMISSIONS for the identity/auth tables
--
-- CLOSES a latent cross-tenant isolation hole: users / organizations /
-- organization_members were live as `TYPE ANY SCHEMALESS PERMISSIONS NONE`
-- (created implicitly via INSERT — identity-vessel's SCHEMA_AUTOAPPLY is off in
-- the substrate deployment and user-vessel, the nominal schema owner, is not
-- deployed). One tenant is seeded today and every vessel connects as SurrealDB
-- ROOT (which bypasses record PERMISSIONS), so this is LATENT, not a live leak —
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
-- APPLIED LIVE 2026-07-23 (operator, root session, individually) to the running
-- learning_loop DB — this file makes that durable across a FRESH deploy. To take
-- effect on a fresh DB it must be applied by the owning path: either
--   (a) identity-vessel with SCHEMA_AUTOAPPLY=true AND this file added to the
--       migration list in src/index.ts (note: that also applies 001-003), or
--   (b) the deployment-repo init-container, or
--   (c) user-vessel deployed as the nominal owner.
-- The owner decision is deliberately left to the deploy layer (law 11) — see the
-- filed gap `identity-tenant-isolation-fresh-deploy-wiring`.
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
