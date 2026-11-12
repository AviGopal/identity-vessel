-- identity-vessel — api_key owner_kind may be 'person'
--
-- 'person': a key one person holds as their own, whose rows other vessels take as that
-- person's own (records stamps role person for nothing else). No derivation produces it and
-- no issuer may declare it: an admin marks an existing key so with apiKey_write owner_kind
-- (src/resolvers/grant-scope.ts). 005 asserted the four earlier values, so the field is
-- redefined with the fifth; every value it allowed stays allowed.
DEFINE FIELD OVERWRITE owner_kind ON api_key TYPE option<string>
  ASSERT $value = NONE OR $value IN ["system", "operator", "peer", "person", "unclassified"];
