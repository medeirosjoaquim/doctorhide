# doctorhide — SaaS Readiness

**Overall: 3/10**

doctorhide has a genuinely solid zero-knowledge crypto core and a broad, meaningful security test suite, but it is a single-owner dev prototype, not a SaaS. The single biggest blocker is the total absence of tenancy and billing: every resource hangs off one Django user, so there are no organizations, teams, roles, plans, or payment path to build a multi-customer product on. Compounding it, the app ships unsafe production defaults (DEBUG=True, hardcoded SECRET_KEY) and has no version control, CI, deploy artifacts, backups, or account-recovery email.

## Scores by dimension

- product-core — 6/10 — coherent CRUD but read-only API, no versioning
- security-auth — 4/10 — strong crypto, unsafe Django prod defaults
- tenancy-billing — 0/10 — single-owner only, no orgs or billing
- data-lifecycle — 2/10 — overwrite-on-update, hard delete, no backups
- api-integrations — 2/10 — two read-only GETs, no writes/docs/limits
- ops-deploy — 2/10 — env config only, no build/ship/run pipeline
- ux-onboarding — 4/10 — MFA path solid, no email/reset/settings
- quality-testing — 5/10 — strong tests, no git/CI/coverage/lint
- compliance-legal — 2/10 — no audit log, ToS, deletion, or export
- reliability-scale — 2/10 — single Postgres, no cache/async/HA

## What it does well

- Genuine zero-knowledge crypto: PBKDF2-SHA256 600k + Fernet, per-project salt, passphrase never stored, verifier-based unlock (vault/crypto.py)
- Coherent end-to-end UI: signup, mandatory TOTP, projects, secret CRUD, API key mint/revoke
- Mandatory TOTP + static backup codes with working PDF download
- Hashed dh_live_/dhk_ API keys with one-time display, expiry, revocation, last_used_at
- API design preserves zero-knowledge: returns ciphertext + KDF params for client-side decrypt
- Broad, meaningful ~204-test suite covering crypto, authz, API security, MFA, lifecycle
- Env-based DB config and clean secret hygiene in .gitignore

## TODO

### Feasible now

- [ ] (S) [FEASIBLE] Move SECRET_KEY to env, fail fast when unset in prod — doctorhide/settings.py:30; committed insecure key allows session/signature forgery
- [ ] (S) [FEASIBLE] Drive DEBUG from env defaulting False — doctorhide/settings.py:33; DEBUG=True leaks tracebacks/settings in prod
- [ ] (S) [FEASIBLE] Populate ALLOWED_HOSTS from env — doctorhide/settings.py:35; no host-header protection and blocks prod serving
- [ ] (S) [FEASIBLE] Require DB credentials via env, drop default doctorhide/doctorhide — doctorhide/settings.py:93-99; guessable defaults risk insecure shipping
- [ ] (S) [FEASIBLE] Add production security settings gated on not DEBUG (SSL redirect, HSTS, secure/httponly/samesite cookies, nosniff) — doctorhide/settings.py; critical for a credential-transmitting app
- [ ] (S) [FEASIBLE] Enable persistent DB connections (CONN_MAX_AGE, CONN_HEALTH_CHECKS) — doctorhide/settings.py DATABASES; new connection per request caps throughput
- [ ] (S) [FEASIBLE] Throttle/batch the per-request last_used_at write — iam/authentication.py; gate behind a cache timestamp to avoid write amplification on the hot path
- [ ] (S) [FEASIBLE] Add DRF throttling for load shedding and brute-force protection — doctorhide/settings.py REST_FRAMEWORK; no DEFAULT_THROTTLE_CLASSES today, a leaked key faces no cap
- [ ] (S) [FEASIBLE] Add pagination to the secrets list endpoint — vault/api.py:30; secrets_list returns all key names unbounded
- [ ] (S) [FEASIBLE] Introduce an API version prefix (/v1/) for integration routes — doctorhide/urls.py:26, vault/api_urls.py; lets the API evolve without breaking consumers
- [ ] (S) [FEASIBLE] Add a delete-secret endpoint to the API — vault/api.py, vault/api_urls.py; a leaked secret can only be removed via UI today
- [ ] (S) [FEASIBLE] Replace ?reveal GET param with a POST reveal action — vault/views.py:74-79; GET leaks the targeted secret id into history and access logs
- [ ] (S) [FEASIBLE] Add project rename and delete in the UI — vault/views.py:33-92, vault/urls.py; only create + detail exist (delete cascades via on_delete)
- [ ] (S) [FEASIBLE] Add django-cors-headers and configure allowed origins — doctorhide/settings.py INSTALLED_APPS/MIDDLEWARE; browser-origin integrations are blocked today
- [ ] (S) [FEASIBLE] Document the ciphertext format and ship a client decrypt helper — vault/crypto.py:25-55, README/DOCS_PAGE.md; consumers must reverse-engineer the PBKDF2+Fernet layout
- [ ] (S) [FEASIBLE] Add a lightweight unauthenticated health/readiness endpoint — doctorhide/urls.py + new health view; /healthz + /readyz (SELECT 1) for LB/orchestrator probes
- [ ] (S) [FEASIBLE] Reconsider User->Project->Secret CASCADE so account deletion does not silently destroy secrets — vault/models.py:28; pair with soft-delete or PROTECT
- [ ] (S) [FEASIBLE] Pin dependencies with a reproducible manifest/lockfile — repo root requirements.txt (+ requirements-dev.txt) or pyproject.toml; no manifest exists, builds non-reproducible
- [ ] (S) [FEASIBLE] Expose a read-only audit log view to project/account owners — vault/urls.py + view over the new AuditLog model; lets customers verify who read which secret
- [ ] (S) [FEASIBLE] Author and serve Terms of Service and Privacy Policy pages with footer links — /terms and /privacy routes + templates, accounts/templates/accounts/base.html; routing is trivial (legal text is separate)
- [ ] (S) [FEASIBLE] Capture ToS/Privacy consent at signup with version + timestamp — accounts/models.py (accepted_terms_version, accepted_at) + signup form/view; auditable proof of consent
- [ ] (S) [FEASIBLE] Publish a security disclosure policy and security.txt — /.well-known/security.txt route + /security page + SECURITY.md; standard for a security product
- [ ] (S) [FEASIBLE] Add a first-login getting-started empty state guiding first project + secret — accounts/templates/accounts/home.html, vault/templates/vault/projects.html; improves activation
- [ ] (S) [FEASIBLE] Polish inline form error messaging across signup/login/MFA — accounts/templates/accounts/signup.html, login.html, totp_verify.html, _pw_field.html; reduces onboarding drop-off
- [ ] (S) [FEASIBLE] Verify /docs is linked in nav and reachable for new users — accounts/templates/accounts/base.html, accounts/urls.py; confirm discoverability of integration guidance
- [ ] (S) [FEASIBLE] Explicitly configure a shared session store for multi-host correctness — doctorhide/settings.py SESSION_ENGINE; horizontal scaling currently works only by accident via default DB sessions
- [ ] (M) [FEASIBLE] Add rate limiting on login, TOTP, and API key auth — accounts/views.py, iam/authentication.py + settings; no brute-force protection on auth endpoints
- [ ] (M) [FEASIBLE] Add API key expiry/rotation/last-used lifecycle controls — iam/models.py, iam/authentication.py; long-lived keys lack lifecycle controls
- [ ] (M) [FEASIBLE] Split settings dev/prod and wire check --deploy — doctorhide/settings.py; prevents unsafe deploys from dev defaults
- [ ] (M) [FEASIBLE] Add a write API to create/update secrets (client-encrypted ciphertext) — vault/api.py, vault/api_urls.py; automation can read but never push secrets
- [ ] (M) [FEASIBLE] Add pagination, search, and filtering to secret lists (UI + API) — vault/views.py:75, vault/api.py:30; both enumerate all secrets unbounded
- [ ] (M) [FEASIBLE] Add .env / JSON bulk import and export — vault/views.py, vault/api.py; table-stakes for onboarding and CI use
- [ ] (M) [FEASIBLE] Install drf-spectacular and expose OpenAPI schema + Swagger/Redoc — settings INSTALLED_APPS/REST_FRAMEWORK, doctorhide/urls.py; no machine-readable contract exists
- [ ] (M) [FEASIBLE] Add a SecretVersion history model and write a version on every update — vault/models.py + migration, vault/views.py:128; update overwrites ciphertext in place with no rollback
- [ ] (M) [FEASIBLE] Convert secret and project deletion to soft-delete with a recovery window — vault/models.py (deleted_at), vault/views.py:140, vault/api.py; hard delete + CASCADE destroys the only copy
- [ ] (M) [FEASIBLE] Add an AuditLog model and log all secret access, mutation, and auth events — vault/models.py + emit from vault/api.py, vault/views.py, accounts/views.py; the top compliance gap for a secrets manager
- [ ] (M) [FEASIBLE] Add a management command for app-level encrypted backup of projects/secrets — vault/management/commands/backup_secrets.py; no backup tooling exists, dump preserves ciphertext (zero-knowledge safe)
- [ ] (M) [FEASIBLE] Add a per-project / GDPR data export endpoint (ciphertext bundle) — vault/api.py or accounts/views.py + serializer; portability/off-boarding while preserving zero-knowledge
- [ ] (M) [FEASIBLE] Implement self-service account deletion with cascade erasure + TOTP re-auth — accounts/urls.py, accounts/views.py; handle ServiceAccount.created_by PROTECT (iam/models.py:27); right-to-erasure
- [ ] (M) [FEASIBLE] Implement password reset flow (request, token link, confirm) — accounts/urls.py, accounts/views.py, new templates; without it, mandatory TOTP makes forgotten passwords a hard lockout
- [ ] (M) [FEASIBLE] Add email verification on signup — accounts/models.py, accounts/views.py, new templates; prevents typo/unverified accounts (depends on email backend)
- [ ] (M) [FEASIBLE] Add an MFA recovery path for users who lose device and backup codes — accounts/views.py, accounts/admin.py; mandatory TOTP with no recovery guarantees support-blocking lockouts
- [ ] (M) [FEASIBLE] Configure structured (JSON) logging with a dedicated auth/IAM logger — doctorhide/settings.py LOGGING; no LOGGING block exists, needed for operational/security audit trail
- [ ] (M) [FEASIBLE] Add a production WSGI server (gunicorn) and static serving (whitenoise + STATIC_ROOT) — settings MIDDLEWARE + deps; app runs on dev runserver with no prod static handling
- [ ] (M) [FEASIBLE] Write a Dockerfile for the application — repo root; multi-stage Python 3.13 image installing from lockfile, collectstatic, gunicorn
- [ ] (S) [FEASIBLE] Write docker-compose for app + Postgres — repo root; replaces the hand-typed docker run with app + Postgres 17 + healthchecks + migrate step
- [ ] (M) [FEASIBLE] Adopt pytest-django with pytest.ini and conftest.py — pytest.ini, conftest.py + requirements-dev; tests run only via Django runner, no markers/fixtures
- [ ] (M) [FEASIBLE] Add linting/formatting (ruff or black+flake8+isort) config — pyproject.toml; no linter/formatter installed or configured
- [ ] (M) [FEASIBLE] Add mypy type checking with django-stubs/drf-stubs — requirements-dev + pyproject; baseline run over vault/crypto.py and auth backends catches bugs early
- [ ] (S) [FEASIBLE] Add coverage measurement with a fail-under threshold — pytest-cov/.coveragerc wired into CI; the ~204 tests have no quantified coverage gate
- [ ] (S) [FEASIBLE] Add a pre-commit config wiring format/lint/type hooks — .pre-commit-config.yaml; shifts enforcement left
- [ ] (M) [FEASIBLE] Add tests for onboarding/UX flows (signup, login, docs, settings, reset) — accounts/tests.py (~60 bytes today); only MFA is meaningfully tested
- [ ] (M) [FEASIBLE] Make settings production-safe end to end (DEBUG, ALLOWED_HOSTS, SECRET_KEY, security headers) — doctorhide/settings.py:30-35; app is unservable in production as configured
- [ ] (L) [FEASIBLE] Build an account settings page (change password, change/verify email, regenerate MFA, manage own API keys) — accounts/views.py, accounts/urls.py, new settings template; no self-service surface post-onboarding
- [ ] (L) [FEASIBLE] Introduce secret versioning / rotation with history + restore in UI and API — vault/models.py:53-68, vault/views.py:116-133, vault/api.py; core gap, single ciphertext column overwrites silently
- [ ] (L) [FEASIBLE] Add write endpoints to create/update/rotate/delete secrets via the project API — vault/api.py, vault/api_urls.py, vault/crypto.py, vault/models.py; CI/CD needs to push and rotate
- [ ] (L) [FEASIBLE] Implement outbound webhooks for secret lifecycle events (model + HMAC signing) — new vault/webhooks.py + WebhookEndpoint model; integrators want to react to secret.rotated/created
- [ ] (L) [FEASIBLE] Introduce an Organization model as the root tenant for all resources — new organizations/ app; add org FK to Project, ServiceAccount, AuditLog; foundational tenancy refactor
- [ ] (L) [FEASIBLE] Add Membership model with roles (owner/admin/member/viewer) and migrate ownership checks — new Membership + DRF permission class; rewrite owner=request.user filters in vault/views.py:9,15, iam/views.py
- [ ] (M) [FEASIBLE] Add Plan and Subscription models with feature flags and quota limits — new billing/ app; monetization backbone, none exist today
- [ ] (M) [FEASIBLE] Enforce usage quotas at create-time for projects, secrets, seats, API keys — vault/views.py, iam/views.py create paths reading the org's active plan; turns plans into real limits
- [ ] (M) [FEASIBLE] Build self-serve billing UI (plan selection, upgrade/downgrade/cancel, payment method, invoices) — new billing/ views + templates; depends on Plan/Subscription + Stripe
- [ ] (M) [FEASIBLE] Publish a Python SDK and curl quickstart over dhk_/dh_live_ Bearer auth — new sdk/ directory, docs from OpenAPI; lowers integration friction for the client-side decrypt flow

### Needs infrastructure

- [ ] (S) [INFRA] Initialize git and push to a remote with branch protection — git init at repo root (.gitignore present) + GitHub repo + required status checks; prerequisite for all CI gating
- [ ] (S) [INFRA] Integrate Sentry (or equivalent) for error tracking — settings + sentry-sdk[django], DSN from env, PII scrubbing; no error tracking exists (needs Sentry account)
- [ ] (S) [INFRA] Add dependency vulnerability scanning (pip-audit or Dependabot) — CI step or .github/dependabot.yml; must catch CVEs in cryptography/Django/psycopg
- [ ] (M) [INFRA] Add a GitHub Actions CI workflow running the suite against a Postgres service — .github/workflows/ci.yml; the strong 204-test suite never runs automatically (needs Actions runner)
- [ ] (M) [INFRA] Add a CACHES backend (Redis) and point sessions/throttling at it — settings CACHES + SESSION_ENGINE; foundation for rate limiting, fast sessions, reduced DB load (needs Redis)
- [ ] (M) [INFRA] Configure a real transactional email provider and Django email backend — settings EMAIL_BACKEND + provider keys; password reset, verification, dunning all depend on it (needs SES/Postmark/SendGrid)
- [ ] (M) [INFRA] Expose Prometheus metrics — django-prometheus + /metrics route; no metrics today (needs a scraper)
- [ ] (M) [INFRA] Provision automated Postgres backups with PITR and off-site retention — managed Postgres + WAL archiving; single DB with no backups is data-loss waiting to happen
- [ ] (M) [INFRA] Terminate TLS at the edge — deployment proxy/LB; HSTS/secure cookies need real TLS
- [ ] (M) [INFRA] Move prod secrets into KMS/secret store — deployment secrets mgmt; prod secrets should not live in .env on disk
- [ ] (M) [INFRA] Provision a task queue/worker for reliable webhook delivery with retries — Celery/RQ + Redis; synchronous delivery blocks requests and drops events on failure
- [ ] (L) [INFRA] Introduce Celery + a worker for async/offloadable work — new doctorhide/celery.py + broker; no async infra for email, audit shipping, key rotation, batch jobs
- [ ] (L) [INFRA] Integrate Stripe Billing (checkout, customer, subscription lifecycle, webhooks) — new billing/ app + Stripe SDK + webhook endpoint; net-new revenue collection (needs Stripe account)
- [ ] (M) [INFRA] Add email subsystem for billing/account lifecycle (invites, receipts, dunning, trial) — settings EMAIL_BACKEND + invite/notification flows in accounts/; self-serve SaaS impossible without email
- [ ] (L) [INFRA] Stand up HA Postgres (replica + failover + PgBouncer) — managed Postgres + replica routing in settings DATABASES; single Postgres is a single point of failure

### Business / legal / out of code scope

- [ ] (S) [SCOPE] Define breach/key-compromise response policy — docs/SECURITY.md; required trust/compliance process for a secrets SaaS
- [ ] (S) [SCOPE] Write and exercise a disaster-recovery / restore runbook — new docs file + dry-run restore; backups are worthless if restore is untested
- [ ] (S) [SCOPE] Define a data-retention and account-deletion policy — product/legal doc paired with soft-delete fields; how long deleted data is recoverable and when purged
- [ ] (S) [SCOPE] Define a support/contact channel surfaced in the UI for lockout/onboarding help — accounts/templates/accounts/base.html footer; business decision on support address/SLA
- [ ] (S) [SCOPE] Define data/log retention limits and a breach-notification runbook; publish subprocessor list + customer DPA — non-code policy docs; GDPR Art. 33/34 and B2B buyer requirements
- [ ] (M) [SCOPE] Write an operations runbook — new RUNBOOK.md; deploy/rollback, env vars, migrations, backup/restore, SECRET_KEY/crypto key rotation, incident response
- [ ] (M) [SCOPE] Define pricing tiers, terms of service, and refund/cancellation policy — product/business + legal; must precede the Plan model and Stripe product setup
- [ ] (M) [SCOPE] Draft the legal text for ToS, Privacy Policy, DPA, and breach-notification process — counsel review, then drop into /terms and /privacy templates

## How this maps to work

The `[FEASIBLE]` items are pure-code changes an implementation workflow can pick up directly; `[INFRA]` items need an external account or running service first, and `[SCOPE]` items are business/legal decisions that must be made before or alongside the related code.
