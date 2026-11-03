-- identity-vessel — api_key owner_node
--
-- The node a 'peer' key was issued for: an issuer that declares owner_kind 'peer' at issue
-- (resolvers/issue-key.ts) names the joining node, and apiKeyClass (src/resolvers/key-class.ts)
-- serves that name as the key's owner_node. No other key carries it, and no existing row is
-- given one: a key issued before a peer could be declared stays as its owner_kind reads.
--
-- Declared before any writer sets it: api_key is SCHEMAFULL, so an undeclared field is
-- dropped from every write. Optional, because only peer keys carry it.
DEFINE FIELD OVERWRITE owner_node ON api_key TYPE option<string>;
