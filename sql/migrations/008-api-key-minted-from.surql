-- identity-vessel — api_key minted_from / minted_at
--
-- A key a person makes for themselves (src/resolvers/person-key.ts) is minted under a short person-session token that
-- names the key the person signed in with. The new row records that key's id and when, so every person key can be
-- traced to the sign-in that made it: a key made by a sign-in that was not a person's is visible, not silent. Absent on
-- every key issued another way.
DEFINE FIELD OVERWRITE minted_from ON api_key TYPE option<string>;
DEFINE FIELD OVERWRITE minted_at ON api_key TYPE option<datetime>;
