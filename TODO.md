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

_(24 feasible tasks implemented on branch `feat/saas-todo-feasible`; suite now 301 tests, all green. The 3 tenancy/RBAC tasks below remain unchecked — deferred: invasive, needs dedicated effort.)_

### Feasible now

- [x] (S) [FEASIBLE] Move SECRET_KEY to env, fail fast when unset in prod — doctorhide/settings.py:30; committed insecure key allows session/signature forgery
- [x] (S) [FEASIBLE] Drive DEBUG from env defaulting False — doctorhide/settings.py:33; DEBUG=True leaks tracebacks/settings in prod
- [x] (S) [FEASIBLE] Populate ALLOWED_HOSTS from env — doctorhide/settings.py:35; no host-header protection and blocks prod serving
- [ ] (S) [FEASIBLE] Require DB credentials via env, drop default doctorhide/doctorhide — doctorhide/settings.py:93-99; guessable defaults risk insecure shipping
- [x] (S) [FEASIBLE] Add production security settings gated on not DEBUG (SSL redirect, HSTS, secure/httponly/samesite cookies, nosniff) — doctorhide/settings.py; critical for a credential-transmitting app
- [ ] (S) [FEASIBLE] Enable persistent DB connections (CONN_MAX_AGE, CONN_HEALTH_CHECKS) — doctorhide/settings.py DATABASES; new connection per request caps throughput
- [ ] (S) [FEASIBLE] Throttle/batch the per-request last_used_at write — iam/authentication.py; gate behind a cache timestamp to avoid write amplification on the hot path
- [x] (S) [FEASIBLE] Add DRF throttling for load shedding and brute-force protection — doctorhide/settings.py REST_FRAMEWORK; no DEFAULT_THROTTLE_CLASSES today, a leaked key faces no cap
- [x] (S) [FEASIBLE] Add pagination to the secrets list endpoint — vault/api.py:30; secrets_list returns all key names unbounded
- [ ] (S) [FEASIBLE] Introduce an API version prefix (/v1/) for integration routes — doctorhide/urls.py:26, vault/api_urls.py; lets the API evolve without breaking consumers
- [x] (S) [FEASIBLE] Add a delete-secret endpoint to the API — vault/api.py, vault/api_urls.py; a leaked secret can only be removed via UI today
- [ ] (S) [FEASIBLE] Replace ?reveal GET param with a POST reveal action — vault/views.py:74-79; GET leaks the targeted secret id into history and access logs
- [ ] (S) [FEASIBLE] Add project rename and delete in the UI — vault/views.py:33-92, vault/urls.py; only create + detail exist (delete cascades via on_delete)
- [ ] (S) [FEASIBLE] Add django-cors-headers and configure allowed origins — doctorhide/settings.py INSTALLED_APPS/MIDDLEWARE; browser-origin integrations are blocked today
- [ ] (S) [FEASIBLE] Document the ciphertext format and ship a client decrypt helper — vault/crypto.py:25-55, README/DOCS_PAGE.md; consumers must reverse-engineer the PBKDF2+Fernet layout
- [x] (S) [FEASIBLE] Add a lightweight unauthenticated health/readiness endpoint — doctorhide/urls.py + new health view; /healthz + /readyz (SELECT 1) for LB/orchestrator probes
- [ ] (S) [FEASIBLE] Reconsider User->Project->Secret CASCADE so account deletion does not silently destroy secrets — vault/models.py:28; pair with soft-delete or PROTECT
- [x] (S) [FEASIBLE] Pin dependencies with a reproducible manifest/lockfile — repo root requirements.txt (+ requirements-dev.txt) or pyproject.toml; no manifest exists, builds non-reproducible
- [x] (S) [FEASIBLE] Expose a read-only audit log view to project/account owners — vault/urls.py + view over the new AuditLog model; lets customers verify who read which secret
- [ ] (S) [FEASIBLE] Author and serve Terms of Service and Privacy Policy pages with footer links — /terms and /privacy routes + templates, accounts/templates/accounts/base.html; routing is trivial (legal text is separate)
- [ ] (S) [FEASIBLE] Capture ToS/Privacy consent at signup with version + timestamp — accounts/models.py (accepted_terms_version, accepted_at) + signup form/view; auditable proof of consent
- [ ] (S) [FEASIBLE] Publish a security disclosure policy and security.txt — /.well-known/security.txt route + /security page + SECURITY.md; standard for a security product
- [ ] (S) [FEASIBLE] Add a first-login getting-started empty state guiding first project + secret — accounts/templates/accounts/home.html, vault/templates/vault/projects.html; improves activation
- [ ] (S) [FEASIBLE] Polish inline form error messaging across signup/login/MFA — accounts/templates/accounts/signup.html, login.html, totp_verify.html, _pw_field.html; reduces onboarding drop-off
- [ ] (S) [FEASIBLE] Verify /docs is linked in nav and reachable for new users — accounts/templates/accounts/base.html, accounts/urls.py; confirm discoverability of integration guidance
- [ ] (S) [FEASIBLE] Explicitly configure a shared session store for multi-host correctness — doctorhide/settings.py SESSION_ENGINE; horizontal scaling currently works only by accident via default DB sessions
- [x] (M) [FEASIBLE] Add rate limiting on login, TOTP, and API key auth — accounts/views.py, iam/authentication.py + settings; no brute-force protection on auth endpoints
- [ ] (M) [FEASIBLE] Add API key expiry/rotation/last-used lifecycle controls — iam/models.py, iam/authentication.py; long-lived keys lack lifecycle controls
- [ ] (M) [FEASIBLE] Split settings dev/prod and wire check --deploy — doctorhide/settings.py; prevents unsafe deploys from dev defaults
- [x] (M) [FEASIBLE] Add a write API to create/update secrets (client-encrypted ciphertext) — vault/api.py, vault/api_urls.py; automation can read but never push secrets
- [x] (M) [FEASIBLE] Add pagination, search, and filtering to secret lists (UI + API) — vault/views.py:75, vault/api.py:30; both enumerate all secrets unbounded
- [ ] (M) [FEASIBLE] Add .env / JSON bulk import and export — vault/views.py, vault/api.py; table-stakes for onboarding and CI use
- [x] (M) [FEASIBLE] Install drf-spectacular and expose OpenAPI schema + Swagger/Redoc — settings INSTALLED_APPS/REST_FRAMEWORK, doctorhide/urls.py; no machine-readable contract exists
- [ ] (M) [FEASIBLE] Add a SecretVersion history model and write a version on every update — vault/models.py + migration, vault/views.py:128; update overwrites ciphertext in place with no rollback
- [x] (M) [FEASIBLE] Convert secret and project deletion to soft-delete with a recovery window — vault/models.py (deleted_at), vault/views.py:140, vault/api.py; hard delete + CASCADE destroys the only copy
- [x] (M) [FEASIBLE] Add an AuditLog model and log all secret access, mutation, and auth events — vault/models.py + emit from vault/api.py, vault/views.py, accounts/views.py; the top compliance gap for a secrets manager
- [ ] (M) [FEASIBLE] Add a management command for app-level encrypted backup of projects/secrets — vault/management/commands/backup_secrets.py; no backup tooling exists, dump preserves ciphertext (zero-knowledge safe)
- [ ] (M) [FEASIBLE] Add a per-project / GDPR data export endpoint (ciphertext bundle) — vault/api.py or accounts/views.py + serializer; portability/off-boarding while preserving zero-knowledge
- [ ] (M) [FEASIBLE] Implement self-service account deletion with cascade erasure + TOTP re-auth — accounts/urls.py, accounts/views.py; handle ServiceAccount.created_by PROTECT (iam/models.py:27); right-to-erasure
- [x] (M) [FEASIBLE] Implement password reset flow (request, token link, confirm) — accounts/urls.py, accounts/views.py, new templates; without it, mandatory TOTP makes forgotten passwords a hard lockout
- [ ] (M) [FEASIBLE] Add email verification on signup — accounts/models.py, accounts/views.py, new templates; prevents typo/unverified accounts (depends on email backend)
- [ ] (M) [FEASIBLE] Add an MFA recovery path for users who lose device and backup codes — accounts/views.py, accounts/admin.py; mandatory TOTP with no recovery guarantees support-blocking lockouts
- [x] (M) [FEASIBLE] Configure structured (JSON) logging with a dedicated auth/IAM logger — doctorhide/settings.py LOGGING; no LOGGING block exists, needed for operational/security audit trail
- [ ] (M) [FEASIBLE] Add a production WSGI server (gunicorn) and static serving (whitenoise + STATIC_ROOT) — settings MIDDLEWARE + deps; app runs on dev runserver with no prod static handling
- [ ] (M) [FEASIBLE] Write a Dockerfile for the application — repo root; multi-stage Python 3.13 image installing from lockfile, collectstatic, gunicorn
- [ ] (S) [FEASIBLE] Write docker-compose for app + Postgres — repo root; replaces the hand-typed docker run with app + Postgres 17 + healthchecks + migrate step
- [ ] (M) [FEASIBLE] Adopt pytest-django with pytest.ini and conftest.py — pytest.ini, conftest.py + requirements-dev; tests run only via Django runner, no markers/fixtures
- [ ] (M) [FEASIBLE] Add linting/formatting (ruff or black+flake8+isort) config — pyproject.toml; no linter/formatter installed or configured
- [ ] (M) [FEASIBLE] Add mypy type checking with django-stubs/drf-stubs — requirements-dev + pyproject; baseline run over vault/crypto.py and auth backends catches bugs early
- [ ] (S) [FEASIBLE] Add coverage measurement with a fail-under threshold — pytest-cov/.coveragerc wired into CI; the ~204 tests have no quantified coverage gate
- [ ] (S) [FEASIBLE] Add a pre-commit config wiring format/lint/type hooks — .pre-commit-config.yaml; shifts enforcement left
- [ ] (M) [FEASIBLE] Add tests for onboarding/UX flows (signup, login, docs, settings, reset) — accounts/tests.py (~60 bytes today); only MFA is meaningfully tested
- [x] (M) [FEASIBLE] Make settings production-safe end to end (DEBUG, ALLOWED_HOSTS, SECRET_KEY, security headers) — doctorhide/settings.py:30-35; app is unservable in production as configured
- [x] (L) [FEASIBLE] Build an account settings page (change password, change/verify email, regenerate MFA, manage own API keys) — accounts/views.py, accounts/urls.py, new settings template; no self-service surface post-onboarding
- [x] (L) [FEASIBLE] Introduce secret versioning / rotation with history + restore in UI and API — vault/models.py:53-68, vault/views.py:116-133, vault/api.py; core gap, single ciphertext column overwrites silently
- [x] (L) [FEASIBLE] Add write endpoints to create/update/rotate/delete secrets via the project API — vault/api.py, vault/api_urls.py, vault/crypto.py, vault/models.py; CI/CD needs to push and rotate
- [ ] (L) [FEASIBLE] Implement outbound webhooks for secret lifecycle events (model + HMAC signing) — new vault/webhooks.py + WebhookEndpoint model; integrators want to react to secret.rotated/created
- [ ] (L) [FEASIBLE] Introduce an Organization model as the root tenant for all resources — new organizations/ app; add org FK to Project, ServiceAccount, AuditLog; foundational tenancy refactor _(deferred: invasive, needs dedicated effort)_
- [ ] (L) [FEASIBLE] Scope projects to an org / migrate all owner=request.user resource filters under the org tenant _(deferred: invasive, needs dedicated effort)_
- [ ] (L) [FEASIBLE] Add Membership model with roles (owner/admin/member/viewer) and migrate ownership checks (per-secret RBAC) — new Membership + DRF permission class; rewrite owner=request.user filters in vault/views.py:9,15, iam/views.py _(deferred: invasive, needs dedicated effort)_
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

## Security Hardening Roadmap

_Sourced from the 71-agent security review (June 2026). Prioritizes LastPass failure mitigations first, then broader hardening._

---

### Week 1 — Incident Response Infrastructure

**Goal: be able to "change the locks" in a breach. LastPass's biggest failure was having no kill switch.**

- Phase 1 — Emergency revocation command
  - [x] Add `python manage.py emergency_revoke_all_keys --org=<id> --before=<timestamp>` — `vault/management/commands/emergency_revoke_all_keys.py`; one `QuerySet.update()` call sets `revoked_at=now()` on all matching keys (supports `--actor`, `--dry-run`, naïve/ISO-8601 `--before`)
  - [x] Log mass revocations as `AuditEvent(action='incident.revoke_all_keys')` with operator identity — single summary row, scoped to the org, principal `operator:<actor>`; covered by `vault/tests_emergency_revoke.py` (6 tests)

- Phase 2 — Admin incident API endpoint
  - [x] Add `POST /admin/incident/revoke-all-keys` (superuser + TOTP required) — `vault/incident_views.py`, wired in `doctorhide/urls.py` before the admin catch-all; gates on `is_superuser` + `is_verified()` (django-otp), returns 403 with a denial-coded `AuditEvent` row on each gate miss
  - [x] Rate-limit and log every call to this endpoint — `IncidentRateThrottle` (`vault/throttling.py`, scope `incident`, 3/hour env-tunable), per-user bucket; every call (success, denied, throttled) is recorded in `AuditEvent` with action `incident.revoke_all_keys` and a specific `outcome` code. Covered by `vault/tests_incident_endpoint.py` (9 tests)

- Phase 3 — Forced passphrase rekey
  - [x] Add `Project.requires_rekey` BooleanField (default=False) — `vault/models.py`, migration `vault/migrations/0014_project_requires_rekey.py`
  - [x] Add `POST /projects/<id>/rekey` endpoint: accepts new passphrase, re-derives key, re-encrypts all secret ciphertexts, updates `salt`/`verifier`/`iterations`, invalidates all active sessions — `vault/views.py:project_rekey` (requires OLD + NEW passphrase; re-encrypts every `Secret` + every `SecretVersion` under the new key in a single `transaction.atomic()`; rotates salt/verifier; clears `requires_rekey`; calls `_forget_project_in_all_sessions` to drop the unlock key from every session row; RBAC: `Membership.ROLE_OWNER`)
  - [x] On project unlock, if `requires_rekey=True`, redirect to rekey flow before granting vault access — `vault/views.py:project_unlock` redirects to `vault:rekey` when the flag is set; detail page exposes the flag to the template
  - [x] Log rekey as `AuditEvent(action='project.rekey')` — rows emitted for success, `denied:wrong_old_passphrase`, and `failed:ciphertext_corrupt`; secret_key carries `secrets=N;versions=N;sessions_invalidated=N`. Covered by `vault/tests_rekey.py` (8 tests)

- Phase 4 — Runbook
  - [x] Write `INCIDENT_RESPONSE.md`: breach detection checklist, revocation steps, user notification template, post-mortem template — `docs/INCIDENT_RESPONSE.md` (operator playbook covering detection signals, triage checklist, CLI + API kill switches (matches the Week 1 Phases 1-3 surface), forced-rekey flow, eradication/recovery, user-notification template, blameless post-mortem template, and a quarterly tabletop-exercise program; cross-linked from `RUNBOOK.md` §Incident Response)

---

### Week 2 — Metadata Encryption + Auth Hardening

**Goal: eliminate the plaintext metadata flaw that made LastPass vaults a "highlight reel" for attackers.**

- Phase 1 — Encrypt secret metadata at rest
  - [ ] Encrypt `Secret.tags` (JSONField → TextField with AES-256-GCM using project key) — `vault/models.py:86`; store HMAC-SHA256 of each tag in `hashed_tags` for server-side filtering
  - [ ] Encrypt `WebhookEndpoint.secret` at rest; show plaintext only at creation (same pattern as API keys) — `vault/models.py:243`
  - [ ] Hash `AuditEvent.secret_key` to HMAC-SHA256(`AUDIT_LOG_SALT`, key) — `vault/models.py:218`; add `AUDIT_LOG_SALT` env var to settings

- Phase 2 — Account lockout + rate limiting
  - [ ] Install `django-axes`; configure `AXES_FAILURE_LIMIT=5`, `AXES_COOLOFF_DURATION=30min` — `accounts/views.py:134`, `doctorhide/settings.py`
  - [ ] Apply `@throttle_classes([LoginThrottle])` to login, TOTP verify, and password-reset endpoints
  - [ ] Add `'auth_login': '5/min'`, `'auth_mfa': '3/min'`, `'auth_reset': '3/hour'` to `DEFAULT_THROTTLE_RATES` — `doctorhide/settings.py:233-238`

- Phase 3 — Email verification enforcement + token expiry
  - [ ] Enforce `email_verified=True` before granting vault access — `accounts/views.py:210`
  - [ ] Add `expires_at` field to `EmailVerificationToken` (24h TTL) — `accounts/models.py:14-26`
  - [ ] Create management command `cleanup_expired_tokens` (run nightly)

---

### Week 3 — Audit Completeness

**Goal: close the silent exfil gap — every access must leave a trace.**

- Phase 1 — Batch and bulk endpoint logging
  - [ ] Add `audit.record(request, 'secret.batch_get', ...)` before return in `secrets_batch_get` — `vault/api.py:135`; this is the biggest audit gap
  - [ ] Add `MAX_BATCH_SIZE = 100` limit check at `vault/api.py:109` to prevent single-request vault dumps
  - [ ] Log validation errors and DB exceptions in `import_secrets` — `vault/api.py:559-601,640-645`

- Phase 2 — Missing endpoint coverage
  - [ ] Add `audit.record(request, 'secret.describe', ...)` to `secret_describe` — `vault/api.py:243-259`
  - [ ] Log failed project unlock attempts as `AuditEvent(action='project.unlock', outcome='failed')`
  - [ ] Log webhook endpoint creation/modification

- Phase 3 — Organization scoping
  - [ ] Pass `organization=project.organization` to all `AuditEvent.objects.create()` calls in `vault/audit.py:45-52`
  - [ ] Enable future `GET /v1/audit?organization=<id>` filtered queries

- Phase 4 — Webhook replay hardening
  - [ ] Add `timestamp` (ISO-8601) and `nonce` (uuid4 hex) to all webhook payloads — `vault/webhooks.py:117-139`
  - [ ] Document consumer-side validation: reject events older than 5 min, deduplicate by nonce

---

### Week 4 — Cryptographic Modernization + Key Session Isolation

**Goal: upgrade crypto primitives and remove the derived key from the database-backed session store.**

- Phase 1 — Argon2id support
  - [ ] Add `Project.kdf` field (choices: `pbkdf2` / `argon2id`, default `argon2id` for new projects) — `vault/models.py`
  - [ ] Update `derive_key()` in `vault/crypto.py` to dispatch to PBKDF2HMAC or Argon2id based on `kdf`
  - [ ] On unlock, if `kdf == 'pbkdf2'`, surface optional migration offer: POST `/projects/<id>/migrate-kdf` re-derives under Argon2id transparently
  - [ ] Argon2id params: `time_cost=2`, `memory_cost=65536` (512MB)

- Phase 2 — AES-256-GCM for new secrets
  - [ ] Add `SecretVersion.algorithm` field (`fernet` / `aesgcm`) — new secrets use AES-256-GCM; old ciphertexts remain readable via Fernet
  - [ ] Update `vault/crypto.py` encrypt/decrypt to dispatch by algorithm field
  - [ ] Add `hmac.compare_digest()` for constant-time verifier comparison — `vault/crypto.py:45` (5 min quick win)

- Phase 3 — Key session isolation
  - [ ] Move derived key storage from Django database-backed session to ephemeral in-memory cache (e.g. `cachetools.TTLCache` keyed by session ID) — `vault/views.py:122,130`
  - [ ] Set 15-minute TTL; on expiry, vault auto-locks and prompts for passphrase re-entry
  - [ ] Use `PyNaCl` `sodium_memzero` equivalent to clear key bytes from memory after use

---

### Week 5 — Passphrase Strength + Webhook CRUD

**Goal: prevent weak passphrase registration; add managed webhook lifecycle.**

- Phase 1 — Passphrase entropy enforcement
  - [ ] Install `zxcvbn`; add validator: score < 3 → reject with helpful message — `vault/views.py:98`
  - [ ] Minimum effective strength equivalent to 16+ random chars or 4+ uncommon words
  - [ ] Add client-side `zxcvbn.js` strength meter on project creation form

- Phase 2 — Passphrase rekey endpoint (depends on Week 1 Phase 3)
  - [ ] Complete `POST /projects/<id>/rekey`: re-encrypt all versions of all secrets under new passphrase
  - [ ] On rekey completion, invalidate all active sessions for the project
  - [ ] Write test: rekey with wrong passphrase → 403; rekey with correct → all ciphertexts updated; old passphrase can no longer unlock

- Phase 3 — Webhook CRUD API
  - [ ] Add `GET/POST /projects/<id>/webhooks/` and `DELETE /projects/<id>/webhooks/<wid>/` endpoints
  - [ ] Enforce HMAC minimum secret length (32 chars)
  - [ ] Log all webhook endpoint mutations as `AuditEvent`
  - [ ] Return plaintext secret only at creation

---

### Week 6 — Monitoring, Alerting + Compliance Docs

**Goal: detect breaches in progress; close compliance docs gaps.**

- Phase 1 — Metrics instrumentation
  - [x] Install `django-prometheus`; add to `INSTALLED_APPS` and `MIDDLEWARE` — exposes `/metrics` scraped by Prometheus in `docker-compose.yml` — `django-prometheus==2.4.0` pinned in `requirements.txt`; `INSTALLED_APPS` + `PrometheusBeforeMiddleware`/`PrometheusAfterMiddleware` wired in `doctorhide/settings.py`; `/metrics` URL exposed in `doctorhide/urls.py`
  - [x] Add custom counters: `vault_secret_reads_total`, `vault_secret_batch_get_total`, `vault_unlock_failures_total` — `vault/metrics.py` defines all four (plus `vault_security_alerts_total`); call sites in `vault/api.py:secret_detail`, `vault/api.py:secrets_batch_get`, and `vault/views.py:project_unlock` increment on the success/denied outcome paths
  - [x] Import dashboards in Grafana: Django request latency, DB query time, secret access rate, failed auth rate — `monitoring/grafana/dashboards/doctorhide-overview.json` (6 panels) + `monitoring/grafana/provisioning/datasources/prometheus.yml` + `monitoring/grafana/provisioning/dashboards/doctorhide.yml` for auto-load

- Phase 2 — Anomaly alerting
  - [x] Add Prometheus alert rules (`monitoring/alerts.yml`): 5+ failed logins in 15 min, batch_get from new IP, >50 secrets read in 1 min by single key — `monitoring/alerts.yml` with four rules: `DoctorhideIncidentEndpointAbuse`, `DoctorhideFailedUnlockSpike`, `DoctorhideSecretReadAnomaly`, `DoctorhideSecurityAlertFired`; rule_files wired in `monitoring/prometheus.yml`
  - [x] Wire Alertmanager (or Grafana alerts) to email/webhook on rule trigger — `monitoring/alertmanager.yml` with default + critical-severity routing + inhibit rule; `alertmanager` service in `docker-compose.yml`
  - [x] Log all anomaly alerts as `AuditEvent(action='security.alert')` — `vault/alerts.py:track_failed_login` and `_audit_alert`; `AuditEvent.objects.create(action='security.alert', outcome=alert_type, ...)` and the `vault_security_alerts_total` Prometheus counter; covered by `vault/tests_alerts.py` (6 tests) and `vault/tests_login_alert_wiring.py` (3 tests)

- Phase 3 — Compliance documentation
  - [x] Finalize `INCIDENT_RESPONSE.md` with step-by-step breach runbook (from Week 1 Phase 4) — `docs/INCIDENT_RESPONSE.md` updated §2 Detection with the four Prometheus alert rules + the Grafana dashboard pointer
  - [x] Add `cleanup_audit_logs` management command — purge `AuditEvent` older than 90 days (run weekly) — `vault/management/commands/cleanup_audit_logs.py` with `--days` and `--dry-run` flags; default 90 days; covered by `vault/tests_cleanup_commands.py` (4 tests)
  - [x] Add `cleanup_deleted_secrets` management command — hard-delete `Secret` records past 30-day recovery window — `vault/management/commands/cleanup_deleted_secrets.py` with `--days` and `--dry-run` flags; default matches `Secret.RECOVERY_WINDOW.days`; covered by `vault/tests_cleanup_commands.py` (5 tests)
  - [x] Update `SECURITY.md` with all hardening measures, crypto parameters, and responsible disclosure contact — `SECURITY.md` updated: per-environment encryption (Week 8), KDF parameters, rate-limiting, monitoring/alerting/IR section, dashboard + alert rule cross-refs, retention purge schedule

---

### Week 7 — Account Credential Lifecycle + Env Import

**Goal: close the credential-staleness gap (LastPass post-mortem finding: long-lived passwords are a low-friction compromise vector) and finish the round-trip between `.env` exports and imports.**

- Phase 1 — Login password rotation countdown (30 days)
  - [ ] Add `accounts.User.password_changed_at` DateTimeField (default on user creation) + migration — `accounts/models.py`; needed so the rotation check has a reference timestamp
  - [ ] Add `PASSWORD_ROTATION_DAYS` env-driven setting (default `30`, override via env) — `doctorhide/settings.py`; an org that has been breached once may want a tighter window
  - [ ] On successful password-step login, if ``now - password_changed_at > PASSWORD_ROTATION_DAYS`` redirect to the change-password flow before granting TOTP/setup access — `accounts/views.py:login`; the user must clear the change-password step before any other action
  - [ ] Persist `password_changed_at` on every successful password change (settings page, password reset, signup) — `accounts/views.py:password_change`/`password_reset_confirm`/`signup`
  - [ ] Emit `AuditEvent(action='auth.password_rotation', outcome='success'|'denied')` on rotation events — `accounts/views.py`; gap so the compliance trail shows *who* was forced and *when*

- Phase 2 — Admin force-rotate password
  - [ ] Add `accounts.User.must_rotate_password` BooleanField (default False) + migration — `accounts/models.py`; the flag the admin toggles to demand a rotation outside the schedule
  - [ ] On login, if the flag is set, redirect to change-password *before* the rotation countdown check (admin override beats schedule) — `accounts/views.py:login`
  - [ ] Clear `must_rotate_password` after a successful password change — `accounts/views.py:password_change`/`password_reset_confirm`; a successful rotation always satisfies the request
  - [ ] Add a Django admin action **"Force password rotation"** on the User changelist — `accounts/admin.py`; the day-to-day workflow for support/security
  - [ ] Add management command `force_password_rotation --org=<id> [--reason="..."]` that flips the flag for every user in an org in a single `QuerySet.update()` and emits a summary `AuditEvent` — `accounts/management/commands/force_password_rotation.py`; the org-wide kill switch for the credential-staleness incident
  - [ ] Emit `AuditEvent(action='auth.force_password_rotation', outcome='success'|'denied')` for every flip (per-user admin action and bulk command) — gap so the legal record captures *who* flipped the flag and for *which* user(s)

- Phase 3 — Environment variables import (plaintext paste / file upload)
  - [ ] Add a **Import .env** form on the project detail page with a textarea + file-upload widget (auto-fills textarea when a file is chosen) — `vault/templates/vault/project_detail.html`, `vault/views.py`; the day-to-day flow for someone migrating from a `.env` file: paste or drop the file, click import
  - [ ] Parse `KEY=value` lines (one secret per line; ignore blank lines and `#` comments; strip optional surrounding `"`/`'` quotes; support `export FOO=bar` prefix) — `vault/views.py`; the rules every `.env` parser in the wild obeys, so users don't have to clean their file first
  - [ ] For each parsed line, encrypt the *plaintext* value with the project key from the session (only allowed when the project is unlocked) and create/update the `Secret` row — `vault/views.py`, `vault/crypto.py`; this is the *only* code path in the app that the server is allowed to encrypt on the user's behalf, and the "project unlocked" gate is the entire safety
  - [ ] Skip malformed lines (no `=`, empty key, value containing a newline) with a per-line warning surfaced in the response so the user can fix and retry — `vault/views.py`; the common gotcha is a stray `=` inside a base64 value, which should not nuke the whole import
  - [ ] Add a confirm step: show a *preview* of the parsed `KEY -> redacted_value` (e.g. `DB_PASSWORD -> ******** (32 chars)`) before the user clicks the final **Import** button, so a pasted prod file doesn't accidentally land in a dev project — `vault/templates/vault/project_detail.html`; the "did I really mean to do this?" affordance
  - [ ] Validate the project is unlocked before showing the form (lock the form / link to unlock if the key isn't in the session) — `vault/views.py`; the project key must be in scope, otherwise the server has no way to encrypt
  - [ ] Add `MAX_IMPORT_LINES` (default 1000) and `MAX_LINE_BYTES` (default 8 KB) caps to bound a single import — `vault/views.py`; prevents a pasted 50 MB file from holding the request hostage
  - [ ] Emit `AuditEvent(action='secret.import', outcome='success'|'denied:locked'|'denied:format')` with the count of secrets created/updated/skipped — `vault/views.py`; the existing `secret.export` row gets a symmetric `secret.import` companion
  - [ ] Tests: parse round-trip (basic, quoted, `export` prefix, comments, CRLF, BOM, malformed lines); encrypt-on-import path; locked-project path; caps; audit row — `vault/tests_env_import.py`

---

### Week 8 — Environments (dev / staging / prod isolation)

**Goal: make `Project` a container, not a flat namespace. Each environment gets its own passphrase, its own API keys, its own rekey, its own blast radius. A leaked dev creds must never read prod secrets.**

**Shape of the change (the part to review before code):**

```
Organization
  └─ Project (container; no salt/verifier/secrets directly)
       ├─ Environment "development"   (own passphrase, own API keys, own rekey)
       ├─ Environment "staging"       (own passphrase, own API keys, own rekey)
       └─ Environment "production"    (own passphrase, own API keys, own rekey)
            └─ Secret (FK → Environment, not Project)
            └─ EnvironmentAPIKey (FK → Environment, replaces ProjectAPIKey)
       (custom environments are allowed; the three above are seeded on create)
```

URLs change from `/projects/<id>/secrets/...` to `/projects/<id>/envs/<env_slug>/secrets/...`. API gets the same prefix. The rekey, unlock, and emergency-revocation commands all become env-scoped.

**Prototyping note (June 2026):** the project is pre-launch; existing data can be destroyed. Phase 1 therefore does *not* need a careful atomic data migration — old `Secret`/`ProjectAPIKey` rows can be dropped as part of the schema swap, and the migration story simplifies to "delete the old rows, add the new schema, reseed on the next test run". If/when this code moves to a live deployment, the migration tasks in this week will need to grow back the data-backfill, back-compat shims, and idempotency tests.

- Phase 1 — Model + schema swap (no data backfill; pre-launch)
  - [x] Add `vault.Environment` model: FK to Project, `name` (human label), `slug` (URL-friendly; unique per project), `salt`, `iterations`, `verifier`, `requires_rekey`, `created_at`, `updated_at` — `vault/models.py`; the new encryption boundary. **Also added**: `Project` loses its real crypto columns; read-only shim properties (`Project.salt`/`.iterations`/`.verifier`/`.requires_rekey`) delegate to `Project.default_environment` so the dozens of read-only call sites in views/tests keep working through Phase 3. The shims are a temporary convenience removed in Phase 3.
  - [x] Drop `Project.salt`/`Project.iterations`/`Project.verifier`/`Project.requires_rekey` (move to `Environment`) and the now-unused helpers in `vault/crypto.py` that reference them — `vault/models.py`; the project loses its cryptography (replaced by the read-only shim properties above)
  - [x] Migration: drop existing `Secret` and `ProjectAPIKey` rows as a one-shot data migration; the dev/test database is reseeded by Django on the next ``migrate`` run — `vault/migrations/0015_add_environment.py`; the prototyping shortcut (a ``RunPython`` that calls ``Secret.objects.all().delete()`` and ``ProjectAPIKey.objects.all().delete()``). The full data-backfill migration is the task that comes back when this code goes live (see week preamble)
  - [x] Add a unique constraint `unique_together = ('project', 'slug')` and `unique_together = ('project', 'name')` on `Environment` — `vault/models.py`; the slug is the URL key, the name is the UI label. ``slug`` defaults to URL-friendly chars (will be tightened with ``validate_slug`` in Phase 3)
  - [x] Add `Project.default_environment` property that returns the seeded `default` env (or raises ``Environment.DoesNotExist``) — `vault/models.py`; the day-to-day lookup pattern. The reverse FK `project.environments.all()` is the canonical list query
  - [x] Tests: model-level (16 new tests for the Environment model + 6 refactored tests for the now-Environment-scoped `requires_rekey` field) — `vault/tests_environment_model.py`, `vault/tests_requires_rekey_field.py`. No idempotency test (the migration is destructive by design pre-launch). All 544 tests pass (was 526 before Phase 1). Ruff clean on the new/modified files. Phase 1 *also* included a partial test-suite mass-rewrite from Phase 6 (the ``make_project`` factory and the direct ``Project.objects.create(salt=…, verifier=…)`` callers), so the suite stayed green instead of going red across phases

- Phase 2 — Re-key the FKs and rename `ProjectAPIKey`
  - [ ] Add `Secret.environment` FK (`on_delete=CASCADE`, `related_name='secrets'`); drop the old `project` FK in the same migration — `vault/models.py`; the new canonical FK, no back-compat denormalization
  - [ ] Rename `ProjectAPIKey` → `EnvironmentAPIKey` (FK to Environment; new prefix `dhenv_`); drop old `ProjectAPIKey` rows in the migration — `vault/models.py`, `iam/authentication.py`; the old `dhk_` prefix is dead. The old prefix is not accepted by the new code path, period
  - [ ] Update the API key split/verify paths to use the new prefix and resolve the project via `key.environment.project` — `vault/models.py`; the lookup chain is now env → project
  - [ ] Update `vault.crypto` rekey/verify helpers that take a Project to take an Environment instead — `vault/crypto.py`; the cryptography layer follows the new boundary
  - [ ] Tests: FK shape, env→project lookup, new prefix, old prefix rejected, env-scoped key only resolves secrets in its env — `vault/tests_environment_fk.py`

- Phase 3 — Views + URLs + templates
  - [ ] Add `_get_environment(request, project, env_slug)` helper that enforces RBAC and 404s on bad slugs (same opaque-404 rule as `_get_project`) — `vault/views.py`; the new URL resolver
  - [ ] Refactor `project_detail` to render an env selector + a per-env secret list; add `project_envs` (list) and `project_env_create` views — `vault/views.py`, `vault/urls.py`; the project page is now a router, not a secret list
  - [ ] Refactor `secret_add`, `secret_delete`, `api_key_create`, `api_key_revoke`, `secret_versions`, `secret_version_restore`, `project_unlock`, `project_lock`, `project_rekey` to take `env_slug` and resolve through `_get_environment` — `vault/views.py`; the bulk of the view work
  - [ ] Update `vault/urls.py` to the new `/projects/<id>/envs/<env_slug>/...` scheme; the old URL shape is dropped in place (no back-compat redirect needed pre-launch) — `vault/urls.py`
  - [ ] Update `vault/templates/vault/project_detail.html` and add `vault/templates/vault/environment_detail.html`, `environment_create.html`, `_env_selector.html` — the env becomes a first-class UI surface (color-coded badge, switcher in the header, separate lock/unlock buttons)
  - [ ] Auto-seed three envs (`development`, `staging`, `production`) on `project_create` (in addition to the default `default` env for the data migration); user can rename or delete any of them — `vault/views.py:project_create`; the Doppler-style "just works" onboarding
  - [ ] Tests: per-env unlock, per-env lock, per-env rekey, per-env api_key_create/revoke, secret CRUD scoped to env, env create/rename/delete, RBAC per env (owner/admin/member/viewer on the project is inherited by all envs for now) — `vault/tests_environment_views.py`

- Phase 4 — API routes
  - [ ] Add env-scoped URL prefix in `vault/api_urls.py`: `/projects/<id>/envs/<env_slug>/secrets/...`; the old `/secrets/...` routes are dropped in place (no `Sunset` shim needed pre-launch) — `vault/api_urls.py`
  - [ ] Update `secrets_list`, `secrets_batch_get`, `secret_detail`, `secret_rotate`, `secret_restore`, `secret_force_delete`, `secret_list_versions`, `secret_restore_version`, `secret_describe`, `import_secrets`, `export_secrets`, `generate_password` to take an `env_slug` kwarg and resolve through `_get_environment` — `vault/api.py`; the bulk of the API work
  - [ ] Re-scope `ProjectInOrganization` permission to also check the env belongs to the org's project — `organizations/permissions.py`; the auth boundary tightens
  - [ ] Update `ProjectRateThrottle` key to include env slug so a noisy dev env can't starve staging/prod — `vault/throttling.py`; fairness across envs
  - [ ] Tests: env-scoped API key resolves to one env, listing secrets from another env returns 404 (not 403, to keep the tenant boundary opaque), batch_get is env-scoped, export includes `env=...` in the metadata header so a re-import into a different env fails the salt check — `vault/tests_environment_api.py`

- Phase 5 — Incident response becomes env-aware
  - [ ] Update `emergency_revoke_all_keys` to accept `--env=<slug>` (optional; without it, all envs in the org) — `vault/management/commands/emergency_revoke_all_keys.py`; the org-wide scope is now "all envs in all projects in the org"
  - [ ] Update `POST /admin/incident/revoke-all-keys` to accept `env` in the body; the audit row records the env(s) affected — `vault/incident_views.py`, `vault/exception_handler.py`; the throttled-call handler picks up the env from the body
  - [ ] `Project.requires_rekey` is gone; `Environment.requires_rekey` is the new toggle. `project_unlock` for an env is the gated entry; a leaked project passphrase is no longer a meaningful concept (envs have their own) — `vault/views.py`, `vault/models.py`; the Week 1 Phase 3 logic moves down one level
  - [ ] `_forget_project_in_all_sessions` becomes `_forget_environment_in_all_sessions` (and a thin wrapper that does both for org-wide rekey) — `vault/views.py`; same blast-radius semantics, finer granularity
  - [ ] Tests: env-scoped emergency revoke, env-scoped rekey, requires_rekey on Environment, full org-wide revoke still works, audit rows carry the env name — `vault/tests_environment_incident.py`

- Phase 6 — Existing test suite mass-rewrite
  - [ ] Update every test that does `Project.objects.create(name='p', salt=..., verifier=...)` to use the new factory: create project + seed default env, then create the secret under that env — sweep across `vault/tests.py`, `vault/tests_*.py`, `iam/tests.py`, `organizations/tests.py`, `accounts/tests_*.py`
  - [ ] Update the test factory helper `make_project` to also return the default env, so `project.secrets.create(...)` sites become `default_env.secrets.create(...)` — `vault/tests.py` (the helper used by every other test file); this is the most error-prone sweep
  - [ ] Update the pytest pattern in `pytest.ini` if any of the new test files need a different `python_files` glob — `pytest.ini`; only if a new naming convention is introduced
  - [ ] Full suite must end at ≥ 526 tests, all green, ruff clean, no new mypy errors — CI gate. (Pre-launch: a small amount of old test data left over from a stale ``.sqlite3`` or test DB is fine; just blow the DB away and re-``migrate`` if anything looks off.)

- Phase 7 — Runbook + docs
  - [ ] Update `docs/INCIDENT_RESPONSE.md` to mention env-scoped kill switches and the per-env rekey; add a worked example of "leaked dev creds" → revoke dev env only, prod untouched — `docs/INCIDENT_RESPONSE.md`; the playbook is now richer
  - [ ] Update `README.md` quickstart to reflect the new env-aware onboarding (3 seeded envs) and the new URL shape — `README.md`; the first thing a new operator sees
  - [ ] Update `RUNBOOK.md` §Crypto Key Rotation to be per-env, not per-project — `RUNBOOK.md`; ops is the audience
  - [ ] Update `DOCS_PAGE.md` and the in-app `/docs` page with a new "Environments" section (what they are, when to use them, per-env passphrases) — `accounts/docs.html` (or the rendered page); the user-facing help

**Pre-launch simplifications (carried over from the week preamble):**
* no back-compat URL redirects; the old shapes are dropped in place
* no `Sunset` header shim on the old API routes
* no idempotency tests on the destructive migration
* no "keep the old column for one cycle" denormalization; columns are dropped in the migration that adds the new shape
* these simplifications get *reversed* in a future "pre-live hardening" week if/when this code moves behind real customers

---

### Week 9 — Allowed Email Domains (install-time invite-only mode)

**Goal: at install time, an operator can configure a list of email domains (e.g. `acme.com`, `*.acme.com`) and only users with a *verified* email on one of those domains can sign up, verify their email, or log in. When the list is empty, the app is open to anyone (the existing behaviour). This is the standard pattern for B2B SaaS that wants to limit signups to specific companies without building a full SSO stack.**

**Shape of the configuration:**

* `ALLOWED_EMAIL_DOMAINS` env var, comma-separated, optional. Empty = open signup.
* Exact match: `acme.com` matches `john@acme.com`.
* Subdomain wildcard: `*.acme.com` matches `john@mail.acme.com` but not `john@acme.com` (intentional — `*.` is a wildcard prefix, not a base-domain shortcut).
* Case-insensitive on both sides: `John@ACME.com` is normalised before the check.
* Set at install time; not editable from the UI. Changing it requires a deploy.

- Phase 1 — Configuration plumbing
  - [ ] Add `ALLOWED_EMAIL_DOMAINS` to `doctorhide/settings.py` as a list parsed from the env var (comma-separated, whitespace-stripped, lowercased, deduped, empty entries dropped) — `doctorhide/settings.py`; the single source of truth read at request time
  - [ ] Add a helper `accounts.utils.is_email_domain_allowed(email)` that returns True/False against the configured list, with the subdomain-wildcard rule and case normalisation — `accounts/utils.py`; the canonical check used by signup, email verification, and login
  - [ ] Add a helper `accounts.utils.allowed_domains_display()` that returns a human-friendly string of the configured domains (for UI: e.g. `acme.com, *.acme.com`) — `accounts/utils.py`; the UI never sees the raw list to avoid leaking it on error pages
  - [ ] When the list is empty, both helpers short-circuit to True / "open signup" so the existing test suite (which uses `@example.com`-style addresses) keeps passing without per-test opt-outs — `accounts/utils.py`; the default behaviour is "no restriction"
  - [ ] Document the env var in `.env.example`, `RUNBOOK.md` (a new "Access control" subsection), and the in-app `/docs` page — `.env.example`, `RUNBOOK.md`, `accounts/templates/accounts/docs.html`; the operator who deploys the app needs to know the knob exists and the wildcard syntax
  - [ ] Tests: empty list = allow all; exact match; subdomain wildcard; case normalisation; trailing-dot domain (`acme.com.`); whitespace tolerance in the env var — `accounts/tests_allowed_domains.py`

- Phase 2 — Signup gating
  - [ ] Reject signup when the email's domain is not in the allowed list — `accounts/views.py:signup`; the gate runs after the existing username/password validation, before the user is created
  - [ ] Error message: "Signups are limited to [allowed_domains_display()]. Use a different email or contact your administrator." — `accounts/views.py:signup`; explicit enough that the user knows *why* they were rejected and what to do
  - [ ] Skip the check for the *first* superuser created via the `ensure_superuser` management command (the bootstrapping flow) — `accounts/management/commands/ensure_superuser.py`; the install flow must not be blocked by the domain gate
  - [ ] Audit log entry `AuditEvent(action='signup.denied:domain_not_allowed', outcome='denied')` with the rejected email and the configured domains (in the `secret_key` field, since there's no project scope) — `accounts/views.py:signup`; the legal record of *who tried to sign up with what address* and was refused
  - [ ] Tests: signup with allowed email succeeds; signup with disallowed email is rejected; rejection message contains the configured domains; superuser creation via management command is not gated; audit row written — `accounts/tests_signup_gating.py`

- Phase 3 — Email verification and login gating
  - [ ] When the user clicks the email-verification link, re-check the domain before marking the email as verified — `accounts/views.py:verify_email`; the signup-time check could be stale if the allowed list changed, so re-check at verification time
  - [ ] At login, if the user has a verified email whose domain is *not* in the allowed list, deny with a clear message ("Your email domain is no longer permitted. Contact your administrator.") and emit an audit row — `accounts/views.py:login`; covers the case where the allowed list shrinks and a previously-OK user is now blocked
  - [ ] At login, if the user has an *unverified* email, do not block on the domain check (they haven't been verified yet, so they're not yet "in") — `accounts/views.py:login`; the email-verification flow handles the gate
  - [ ] Tests: verification with disallowed email is rejected; login with verified-but-disallowed email is denied; login with unverified email is not blocked on the domain; the login flow's TOTP step still works correctly when the domain gate fires — `accounts/tests_login_gating.py`

- Phase 4 — Superuser bypass + audit
  - [ ] Superusers always bypass the domain check at login, even if their email domain is not in the allowed list — `accounts/views.py:login`; the break-glass admin path (e.g. a CISO whose personal email is not on the list but who must be able to intervene)
  - [ ] Log every domain-gate decision (allow, deny) to the existing `django-axes`-free audit table — `accounts/views.py:signup`, `accounts/views.py:login`, `accounts/views.py:verify_email`; the audit trail for compliance reviews ("who tried to sign up / log in with a disallowed email, and when")
  - [ ] Add a Django system check `accounts.checks.allowed_domains_format` that runs at deploy time and warns if the env var is set but contains a malformed entry (e.g. a wildcard with no dot, a domain with whitespace) — `accounts/checks.py`; catch config bugs at deploy, not in production logs
  - [ ] Tests: superuser with non-allowed email can still log in; every domain-gate decision is audited; malformed env var emits a system check warning — `accounts/tests_superuser_bypass.py`

- Phase 5 — UI & docs
  - [ ] On the signup page, when the allowed list is non-empty, show a small banner ("Signups are limited to {display}") above the form so the user knows the gate exists before they fill in the form — `accounts/templates/accounts/signup.html`; saves a round-trip
  - [ ] On the login page, when the allowed list is non-empty, show the same banner so a user with a now-disallowed email who tries to log in sees *why* — `accounts/templates/accounts/login.html`; turns a confusing 403 into a self-explanatory rejection
  - [ ] On the account settings page, show "Access: {domain}" so the user can see what domain they're on and why — `accounts/templates/accounts/settings.html`; useful for support ("I'm on acme.com, why am I being blocked?")
  - [ ] Update the in-app `/docs` page with an "Access control" section explaining the env var, the wildcard syntax, the superuser bypass, and the audit trail — `accounts/templates/accounts/docs.html`; discoverable from the UI
  - [ ] Update `RUNBOOK.md` §Access control with the same content + a "rotating the allow-list" subsection (changes require a deploy; the env var is read at request time so a rolling restart is sufficient) — `RUNBOOK.md`; the operator-facing runbook
  - [ ] Tests: signup banner present iff list non-empty; login banner present iff list non-empty; settings page shows the user's domain; docs page has the section — `accounts/tests_domain_ui.py`

**Pre-launch simplifications (carried from Week 8's preamble):**
* no `last_login` denormalisation; the check reads ``User.email`` fresh each time
* no per-user override ("this user is allowed even though their domain isn't") pre-launch; if a single contractor needs in, add their email's domain to the env var and re-deploy. The override model comes back in a future "pre-live hardening" week
* no email-aliasing rules (e.g. `+test@`); the check is on the domain part of the address only
* no IDN/Unicode-domain handling; ASCII-only in V1, with a system check that warns if a non-ASCII domain sneaks in

---

## How this maps to work

The `[FEASIBLE]` items are pure-code changes an implementation workflow can pick up directly; `[INFRA]` items need an external account or running service first, and `[SCOPE]` items are business/legal decisions that must be made before or alongside the related code.
