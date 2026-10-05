# Contributing to AegisMCP

Thanks for helping make agent tool execution safer. This project favours small,
reviewable changes that preserve its security guarantees.

## Getting started

```bash
pnpm install
export DATABASE_URL="postgres://aegis:aegis@127.0.0.1:5432/aegis_test"
pnpm --filter @aegis/gateway db:migrate
pnpm run check
```

`pnpm run check` runs typecheck, lint, format check, and the full test suite.
Integration tests need PostgreSQL; unit tests in `apps/gateway` are DB-free by
design (their vitest config forces `DATABASE_URL=""`).

## Ground rules

1. **Never weaken a security control to make a test pass.** If a test is wrong,
   fix the test; if a control blocks legitimate behavior, discuss the change.
2. **Never turn DENY into ALLOW** for convenience.
3. **Fail closed.** Errors on the security path reject; they never fall through.
4. **Never log, persist, or throw secrets.** Credentials, peppers, and raw tool
   arguments must not appear in output, errors, or the database.
5. **Add a regression test for every security fix.**
6. **Reuse existing abstractions.** Policy stays pure data, repositories own SQL,
   the approval service owns approval transitions.
7. **No new dependency without a real problem to solve.**

## Project conventions

- TypeScript, ESM, `verbatimModuleSyntax`; use `import type` for types.
- Domain types are plain, frozen data; transport/SQL concerns stay at the edges.
- Errors returned to callers are generic; detailed reasons are audited only.
- Public identifiers (policy ids, key ids, approval ids) are safe to log; secrets
  are not.

## Adding a policy field

1. Extend `policy/types.ts`.
2. Validate it in `policy/validate.ts` (fail closed on bad shape).
3. Map it in `repositories/mappers.ts` (and store it).
4. Match it in `policy/matcher.ts` without changing decision precedence.
5. Add unit tests (matcher/validate/engine) and, if it affects the API, an admin
   `parsePolicy` case in `routes/admin.ts`.

## Adding a control-plane endpoint

1. Declare the permission it needs in `security/rbac.ts`.
2. Require that permission via the `guard` helper in `routes/admin.ts`.
3. Validate and paginate input; return the standard error shape.
4. Audit the operation (and audit authorization failures).
5. Add a test proving an ordinary `AGENT` credential is refused.

## Migrations

Forward-only, numbered `NNNN_name.sql`, each in its own transaction, with a
comment explaining the security-relevant design choices. There are no down
migrations; roll back with a new forward migration.

## Commits

Prefer small, focused commits. Explain _why_ in the message.
