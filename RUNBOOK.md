# Deployment & Operations Runbook

This document covers deployment, configuration, backup/restore, incident response, and crypto key rotation for doctorhide.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Environment Variables](#environment-variables)
- [Database Migrations](#database-migrations)
- [Deployment](#deployment)
- [Backup & Restore](#backup--restore)
- [SECRET_KEY Rotation](#secret_key-rotation)
- [Crypto Key Rotation](#crypto-key-rotation)
- [Incident Response](#incident-response)
- [Rollback](#rollback)

## Prerequisites

- Python 3.13+
- PostgreSQL 17 (or compatible)
- Docker & Docker Compose (for containerized deployment)
- uv (Python package manager, optional but recommended)
- AWS CLI (if using S3 backups)

## Environment Variables

### Core Django

- **DEBUG** — "1", "true", or "yes" enables debug mode. Must be unset/false in production.
- **SECRET_KEY** — Required in production. A cryptographically secure random key for Django session signing. Never commit to VCS.
- **DJANGO_ENV** — Set to "production" to enable HTTPS hardening (HSTS, secure cookies). Requires SECRET_KEY.
- **ALLOWED_HOSTS** — Comma-separated list of allowed hostnames (default: 127.0.0.1,localhost).
- **LOG_LEVEL** — Root logging level; default is INFO.

### Database

- **POSTGRES_DB** — Database name (default: doctorhide).
- **POSTGRES_USER** — Database user (default: doctorhide).
- **POSTGRES_PASSWORD** — Database password. Must not be committed.
- **POSTGRES_HOST** — Database host (default: 127.0.0.1 for local, "db" in docker-compose).
- **POSTGRES_PORT** — Database port (default: 5433 for local, 5432 in docker-compose).
- **DB_CONN_MAX_AGE** — Connection pool timeout in seconds (default: 0 for dev/test, set to 600+ in production).
- **DB_CONN_HEALTH_CHECKS** — Enable connection health checks (default: false; set to "1" or "true" in production with pooling).

### Session & Cache

- **SESSION_ENGINE** — Session backend (default: django.contrib.sessions.backends.db). Use CACHE or Redis in production.
- **CACHE_BACKEND** — Cache backend (default: django.core.cache.backends.locmem.LocMemCache). Use Redis in production.

### Email

- **EMAIL_BACKEND** — Mail transport (default: django.core.mail.backends.console.EmailBackend for dev). Use SMTP in production.

### API & Security

- **VAULT_API_THROTTLE_RATE** — DRF throttle rate for vault API (default: 1000/min).
- **CORS_ALLOWED_ORIGINS** — Comma-separated list of CORS-allowed origins (empty by default; enable only as needed).

## Database Migrations

### Create migrations

After modifying models, generate migration files:

```bash
/home/asari/doctorhide/venv/bin/python manage.py makemigrations <app>
```

Review the generated file in `<app>/migrations/` before committing.

### Apply migrations

```bash
/home/asari/doctorhide/venv/bin/python manage.py migrate
```

In a multi-host setup, run this on a single leader before bringing the app online.

### Check migration status

```bash
/home/asari/doctorhide/venv/bin/python manage.py showmigrations
```

## Deployment

### Local Development

1. Copy `.env.example` to `.env` and adjust.
2. Start Postgres (either local `docker run` or use docker-compose).
3. Apply migrations: `python manage.py migrate`.
4. Run development server: `python manage.py runserver`.

### Docker Compose

1. Create `.env` with production settings (especially SECRET_KEY, POSTGRES_PASSWORD, ALLOWED_HOSTS).
2. Run: `docker-compose up -d`.
3. Migrations run automatically in the `migrate` service.
4. App listens on `http://localhost:8000`.

### Kubernetes / Cloud Deployment

1. Build image: `docker build -t doctorhide:latest .`.
2. Push to registry.
3. Deploy pod/container with environment variables:
   - Mount or inject SECRET_KEY as a secret.
   - Mount or inject DATABASE credentials as a secret.
   - Set DJANGO_ENV=production, DEBUG=false.
   - Set ALLOWED_HOSTS to your domain(s).
   - Set POSTGRES_HOST to your managed DB endpoint.
4. Run migrations in an init container or as a pre-deploy step.
5. Expose port 8000 (or use a reverse proxy).

## Backup & Restore

### Backup

#### PostgreSQL Dump

```bash
PGPASSWORD=<password> pg_dump -h <host> -p <port> -U <user> -d doctorhide > backup.sql
```

Store `backup.sql` safely (encrypted, off-site, version-controlled).

#### Backup with Timestamp

```bash
PGPASSWORD=<password> pg_dump -h <host> -p <port> -U <user> -d doctorhide > backup-$(date +%Y%m%d-%H%M%S).sql
```

### Restore

```bash
PGPASSWORD=<password> psql -h <host> -p <port> -U <user> -d doctorhide < backup.sql
```

**Warning:** This overwrites the target database. Create a new database or restore to a standby first.

### Verify Restore

```bash
/home/asari/doctorhide/venv/bin/python manage.py migrate --check
```

## SECRET_KEY Rotation

When SECRET_KEY is compromised or rotated for compliance:

1. Generate a new key (e.g., `python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"`).
2. Update the SECRET_KEY environment variable in all deployment targets.
3. Restart all app instances.
4. Old session tokens become invalid; users must re-authenticate.

**Impact:** Users will be logged out. Plan for off-peak hours.

## Crypto Key Rotation

Project secrets are encrypted with keys derived from user-provided passphrases (not stored server-side). To rotate encryption without re-encrypting all secrets:

1. Users can update their project's passphrase in the web UI (generates a new salt, re-encrypts the verifier).
2. The verifier proves the new passphrase matches without storing it.
3. Existing encrypted secrets remain unchanged; users supply the new passphrase on each access.

**No server-side action required.** Rotation is user-driven.

## Incident Response

For breach-specific playbooks (detection checklist, kill-switch command/API
walkthrough, user-notification template, post-mortem template, quarterly
tabletop), see [`docs/INCIDENT_RESPONSE.md`](docs/INCIDENT_RESPONSE.md).
The summary below covers infrastructure-level failures only.

### Database Down

1. Check Postgres is running: `docker ps | grep postgres` or `systemctl status postgresql`.
2. Check logs: `docker logs <postgres-container>` or `journalctl -u postgresql`.
3. If unresponsive, restart: `docker restart <postgres-container>` or `systemctl restart postgresql`.
4. After restart, verify migrations are still applied: `python manage.py migrate --check`.
5. If corrupted, restore from backup (see [Backup & Restore](#backup--restore)).

### Leaked API Key

1. Revoke the key immediately via admin UI or CLI (sets revoked_at timestamp).
2. Audit access logs (`vault.AuditEvent` table) for misuse since key creation.
3. Regenerate a new key for the service account.
4. Update the service's configuration with the new key.

### Compromised User Password

1. Admin can reset the user's password via Django admin.
2. The user's TOTP is NOT reset (user still has their authenticator).
3. If TOTP is also compromised, admin can revoke TOTP recovery and force re-enrollment on next login (see accounts app).
4. Audit user login events (`django.contrib.admin` logs, or custom AuditEvent if enabled).

### Unauthorized Secret Access

1. Review `vault.AuditEvent` entries for the affected project.
2. Soft-delete compromised secrets (30-day recovery window).
3. Regenerate and rotate any leaked secret values in downstream systems.
4. Audit and revoke suspicious API keys for the project.

### DDoS / Rate Limiting

The vault API is throttled at 1000 requests/min per project (configurable via `VAULT_API_THROTTLE_RATE`). If under sustained attack:

1. Tighten throttle rate in environment variables (e.g., 100/min).
2. Deploy a WAF (Web Application Firewall) upstream to block suspicious IPs.
3. Scale horizontally: add more app instances behind a load balancer.

## Rollback

### Rolling Back a Deployment

1. Revert the docker image tag to the previous version: `docker-compose down && docker-compose up -d` (with old image in `.env`).
2. If migrations were applied, do NOT run `migrate` again; the old code expects the old schema.
3. Monitor logs and verify app health.

### Rolling Back a Migration

**Only if a migration was just applied and caused a data loss / schema issue:**

1. Create a new migration that reverses changes: `python manage.py makemigrations <app>` (implement a reverse operation).
2. Apply it: `python manage.py migrate`.
3. **Never** use `migrate <app> <prev_migration_number>` in production without a full backup.

If unable to reverse safely, restore from backup (see [Backup & Restore](#backup--restore)).

## Health Checks

A simple liveness probe:

```bash
curl -i http://localhost:8000/whoami
```

Expected response: 401 (not authenticated) or 200 (if session/API key valid).

Monitor these metrics:

- Postgres connection pool exhaustion (check `pg_stat_activity`).
- Vault API throttle hits (check app logs for `Throttled` messages).
- Audit log growth (table size, monitor for unexpected spikes).
