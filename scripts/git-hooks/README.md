# identity-vessel git hooks

Versioned git hooks for the identity-vessel (API-key + JWT issuer for the metabob system). Installed by running:

```bash
scripts/git-hooks/install.sh
```

This sets `core.hooksPath` to `scripts/git-hooks/` so updates land via `git pull`. Same pattern as the `metabob-devbob` super-repo and the deployment repo.

## Philosophy

identity-vessel is a TS/Bun service. Source lives in `src/`, SQL schema and migrations in `sql/`, ops tooling in `scripts/`, stateless reference docs in `docs/`. The vessel root holds project metadata only.

Anything else accumulates as cruft. The pre-commit hook rejects new cruft at commit time. Existing files are grandfathered.

## Where things go

| You have | Put it in |
|---|---|
| Stateless reference doc (auth flow, JWT claims, key validation) | `docs/<topic>.md` |
| One-off operational script (key generation, key rotation) | `scripts/<verb>-<noun>.sh` |
| Source code | `src/...` |
| SurrealDB migration | `sql/migrations/<NNN>-<slug>.surql` |
| Tests | `test/...` or `tests/...` |
| Status snapshot, fix-complete narrative, migration-plan checklist | nowhere — write a commit message instead |

## What the hook blocks

A commit is rejected when it adds (or renames into) a file that violates any of these rules:

1. **Files at the vessel root** are limited to a small allowlist (`CLAUDE.md`, `README.md`, `package.json`, `tsconfig.json`, `bun.lock`, `Dockerfile`, `.dockerignore`, dotfile configs).
2. **No new top-level markdown** outside `docs/`.
3. **No new test files at root**. Tests live in `test{,s}/`.
4. **No new ad-hoc scripts at root** (`*.sh`, `*.ts`, `*.js`, `*.py`). Operational scripts go in `scripts/`; source in `src/`.
5. **No new SQL/SurrealDB files at root**. They go in `sql/` or `migrations/`.
6. **No new image / video / archive files** outside `docs/assets/`.
7. **New top-level directories** outside the allowed set (`src`, `test`, `tests`, `docs`, `scripts`, `sql`, `migrations`, `packages`, `cli`, `bin`, `.github`, `.minibob`) are rejected.

## Bypass

```bash
git commit --no-verify
```

Use sparingly.

## Related

- The super-repo (`metabob-devbob`) has a parallel hook at `scripts/git-hooks/pre-commit`.
- The deployment repo has the same pattern under its own `scripts/git-hooks/`.
