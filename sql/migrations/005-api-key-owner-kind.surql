-- identity-vessel — api_key owner_kind
--
-- Each key's class, which the apiKeyClass resolver serves (src/resolvers/key-class.ts):
-- 'system' (issued by the seeder to a vessel service), 'operator' (declared an operator's or
-- a person's key at issue), 'unclassified' (untraceable from what the row holds), and 'peer',
-- which readers recognise and no derivation in identity produces.
--
-- Declared before any writer sets it: api_key is SCHEMAFULL, so an undeclared field is
-- dropped from every write. Optional, because every row written before this file has none.
--
-- The existing rows are stamped at unit start by db/migrations.ts (backfillOwnerKind), after
-- the files apply, with the one rule issue-key.ts stamps new keys with (deriveOwnerKind,
-- from the row's name). A row it cannot stamp keeps NONE and is answered by the same rule.
DEFINE FIELD OVERWRITE owner_kind ON api_key TYPE option<string>
  ASSERT $value = NONE OR $value IN ["system", "operator", "peer", "unclassified"];
