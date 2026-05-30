# doctorhide — SaaS TODO Implementation Log

- Branch: `feat/saas-todo-feasible`
- Final test suite total: 301 tests
- Final status: green (all pass, system check clean)
- Implemented: 24 feasible tasks
- Deferred: 3 tenancy/RBAC tasks

## What was implemented (committed)

Settings / ops hardening:

- Load DEBUG from env (default False) — `feat: Load DEBUG from env (default False)` / `test: cover DEBUG-from-env parsing`
- Load SECRET_KEY from env, fail if unset in prod — `feat: load SECRET_KEY from env, require it in production`
- Load ALLOWED_HOSTS from env — `feat: load ALLOWED_HOSTS from env`
- HSTS / secure-cookie / SSL settings gated on a PROD flag — `feat: add HSTS/secure-cookie/SSL settings gated on PROD flag`
- LOGIN_URL / LOGIN_REDIRECT_URL settings — `feat: add LOGIN_URL / LOGIN_REDIRECT_URL settings`
- Structured logging config — `feat: add structured logging config`
- /healthz and /readyz endpoints — `feat: add /healthz and /readyz endpoints`
- Pin dependencies in requirements.txt — `build: pin dependencies in requirements.txt`
- .dockerignore + complete .env.example — `chore: add .dockerignore and complete .env.example` / `chore: document all env vars in .env.example`

Vault API features (AWS Secrets Manager-style, zero-knowledge preserving):

- Random secret generator endpoint — `feat: add random password generator API endpoint`
- Soft-delete + recovery window for secrets — `feat: soft-delete + recovery window for secrets`
- RestoreSecret + ForceDelete endpoints — `feat: RestoreSecret + ForceDelete endpoints`
- Secret write API (create/update) with idempotency token — `feat: secret write API (create/update) with idempotency token`
- BatchGetSecretValue endpoint — `feat: BatchGetSecretValue endpoint`
- ListSecrets pagination + prefix filter — `feat: ListSecrets pagination + prefix filter`
- DescribeSecret metadata endpoint — `feat: DescribeSecret metadata endpoint`
- SecretBinary payload support — `feat: SecretBinary payload support`
- Tagging on secrets + tag filter — `feat: tagging on secrets + tag filter`

Compliance / accounts / API platform:

- Audit log model + access-logging hooks — `feat: audit log model + access-logging hooks`
- Account settings page (change password, view account info) — `feat: account settings page (change password, view account info)`
- Password reset flow (token-based, console email in dev) — `feat: password reset flow (token-based, console email in dev)`
- API rate limiting via DRF throttling — `feat: API rate limiting via DRF throttling on vault dhk_ API`
- OpenAPI schema + Swagger UI — `feat: OpenAPI schema + Swagger UI`

## What was skipped / deferred and why

Three tenancy/RBAC tasks were intentionally left unchecked. They are invasive cross-cutting refactors that touch every ownership check and migration path, and need dedicated effort rather than being safely bundled into an incremental feasible run:

- Introduce an Organization model as the root tenant for all resources
- Scope projects to an org (migrate all `owner=request.user` resource filters under the org tenant)
- Add Membership model with roles + per-secret RBAC

INFRA and SCOPE sections of TODO.md were out of scope for this code-only run (they require external accounts, running services, or business/legal decisions).

## Notes

- Suite grew from a ~204-test baseline to 301 tests.
- A handful of intra-run suite totals dipped (e.g. while wiring throttling and the write API) before settling green at 301; final full run is OK with no failures and a clean system check.
- All work is committed on `feat/saas-todo-feasible`; no pushes were made to protected branches.
