-- identity-vessel — users.password_hash field migration
--
-- The `users` table is owned by user-vessel (sql/001-init-schema.surql), but
-- per user-vessel's CLAUDE.md ("Don't add password hashing, JWT signing, or
-- login/signup routes — those live in identity-vessel"), the password_hash
-- field is identity-vessel's responsibility. This migration adds the field
-- via DEFINE FIELD OVERWRITE so it composes onto user-vessel's existing
-- SCHEMAFULL users table without conflicting with user-vessel's migrations.
--
-- Idempotent: safe to re-run on the deployed canary table.
--
-- Used by: src/resolvers/login.ts (POST /v1/auth/login, /v1/auth/signup)

-- password_hash holds an Argon2id hash produced by Bun.password.hash().
-- option<> so legacy/seeded users without a hash continue to validate;
-- login.ts treats null/missing as "invalid_credentials" (no SSO yet).
DEFINE FIELD OVERWRITE password_hash ON users TYPE option<string>;
