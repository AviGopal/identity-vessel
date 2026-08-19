# identity-vessel — open findings

Three defects found against a live 0.2.0 deployment (the `dashboard-film` namespace) while
filming an unrelated demonstration. Each was reproduced with real requests; every probe below
used a **fabricated canary**, never a live credential. All three are still open.

The credential-echo defect these were found alongside is fixed in `2caa4fbb`; these are not.

---

## 1. `POST /v1/keys/revoke` kills the key but leaves the audit view calling it active

Two revocation paths disagree about what they did.

```
POST /v1/keys/revoke  {"api_key": "<key>"}
  -> {"success":true,"data":{"revoked":true,"key_id":"key_JQwizmTzBika_KfA"}}
  -> POST /v1/keys/validate on that key: valid = false          (key really is dead)
  -> GET  /v1/keys:  key_JQwizmTzBika_KfA ... "status": "active"   <-- WRONG

DELETE /v1/keys/key_JQwizmTzBika_KfA
  -> {"success":true,"data":{"revoked":true,"key_id":"key_JQwizmTzBika_KfA"}}
  -> GET  /v1/keys:  key_JQwizmTzBika_KfA ... "status": "revoked"  <-- correct
```

**Why it matters.** `GET /v1/keys` is the audit surface. An operator who revokes by the POST path
and then lists keys sees the dead key reported as live. The error direction is the safer one — the
key genuinely does not authenticate — but "the listing disagrees with reality" is not a property
an audit view may have, and an operator cannot tell which of the two is lying without separately
validating every key.

This was found because a reviewing agent checked an operator's claim that a leaked key had been
revoked, saw `active` in the listing, and flagged it rather than accepting the claim.

**Suggested fix.** Both paths should write the same state. Whichever field `GET /v1/keys` reads for
`status`, the POST path is not setting it.

---

## 2. `POST /v1/keys/issue` still echoes the presented credential, after `2caa4fbb`

`2caa4fbb` fixed the echo at the `verifyJWT` chokepoint in `src/services/jwt.ts`. It does not
cover `src/resolvers/issue-key.ts:96`, which returns `err.message` from `verifyJwt` verbatim on
its own path.

```
POST /v1/keys/issue   -H "authorization: Bearer mb-FAKE-CANARY-abcdef0123456789"
  -> {"error":{"code":"INVALID_JWT","message":"invalid JWT token: mb-FAKE-CANARY-abcdef0123456789"}}
```

Same class as the fixed defect, same blast radius: credentials in error strings reach logs,
transcripts and screen recordings. It needs the same treatment — map the failure class to a fixed
string rather than passing an exception message through.

---

## 3. `POST /v1/jwt/generate` honours a caller-supplied `role` without checking the caller's scopes

A key that validates as `scopes:["read"], role:"user"` can mint a `role:"admin"` JWT and use it.

```
POST /v1/keys/validate   -> {"valid":true,"scopes":["read"],"role":"user"}
POST /v1/jwt/generate  {"role":"admin", ...}
  -> 200, decoded payload {... "role":"admin", "AC":"apikey_token"}
POST /v1/keys/issue    -H "authorization: Bearer <that JWT>"
  -> 200 {"key":"mb-…","key_id":"key_2ryBmSTwhnj9QjYz"}
DELETE /v1/keys/key_2ryBmSTwhnj9QjYz  -> {"revoked":true}
```

Reproduced independently twice, on two namespaces. Authentication is enforced at the door — no
auth is `401 MISSING_AUTH_HEADER`, a bogus key is `401 INVALID_API_KEY` — so this is not an
open door; it is a **missing check on the requested role**. The presenting key's scopes are
validated and then not consulted when the claim is granted.

Any holder of any valid org key can therefore provision further keys at any role.

Every key minted during these probes was revoked; the probe keys appear in `GET /v1/keys` as
`revoked` (see finding 1 for the caveat about which revoke path updates that field).

---

## Method note

Findings 1 and 3 were reproduced against `dashboard-film`; finding 2 was found by probing the
fixed source rather than reading the diff, which is why it survived the fix that was supposed to
cover it. None of these were found by a test suite — all three came out of using the service and
checking what it actually returned.
