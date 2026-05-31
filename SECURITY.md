# Security Policy

This document outlines security practices, disclosure policy, and guidelines for reporting vulnerabilities in doctorhide.

## Supported Versions

- **1.0.x** — Supported (current)
- **0.x** — End of life

Security updates are released as patches (1.0.1, 1.0.2, etc.) to the currently supported version.

## Reporting a Vulnerability

**Do not** file a public GitHub issue for security vulnerabilities.

Instead, please email **security@doctorhide.com** with:

- A clear description of the vulnerability and impact.
- Steps to reproduce (or a proof of concept if applicable).
- Your contact information (name, email, optionally PGP key).
- If you'd like credit for the disclosure, your preferred name/handle.

We aim to:

- Acknowledge receipt within 24 hours.
- Provide a timeline for a fix within 48 hours.
- Issue a patch and coordinate a responsible disclosure within 7-14 days, depending on severity.
- Credit responsible reporters in release notes (unless you prefer anonymity).

## Security Measures

### Authentication

- **Human users:** Username + password + mandatory TOTP (time-based one-time password) with ±30s drift tolerance.
- **Recovery:** Backup codes (printed once at enrollment, stored securely by user).
- **Password reset:** Email verification token (one-time use, expires).

### API Keys (Service Accounts)

- Prefixed with `dhk_` (doctorhide project key).
- Secrets are SHA-256 hashed; plaintext shown only once at mint.
- Revocation is permanent (revoked_at timestamp prevents use).
- Expiration is optional (enforced server-side).

### Encryption

- **Project secrets:** Encrypted with Fernet (AES-128-CBC + HMAC-SHA256).
- **Key derivation:** PBKDF2 with SHA-256, 600,000 iterations by default (per OWASP recommendations).
- **Per-project salt:** Unique, random, never reused.
- **Passphrase policy:** Never stored server-side. Supplied by client on each access.
- **Verifier:** Encrypted token proving passphrase correctness without storing it.

### Secrets Management

- **Sensitive data never logged:** API keys, passphrases, TOTP secrets, ciphertext excluded from logs.
- **Environment variables:** SECRET_KEY and database passwords loaded from env (not hardcoded).
- **gitignore:** `.env`, `secrets/`, local DB files, key/cert files excluded.

### HTTPS & Transport Security

- **TLS enforcement:** In production (DJANGO_ENV=production), HTTPS is mandatory:
  - SECURE_SSL_REDIRECT = True
  - HSTS (HTTP Strict-Transport-Security) enabled with 1-year max-age
  - HSTS preload candidate
  - Secure cookies (SESSION_COOKIE_SECURE, CSRF_COOKIE_SECURE)

### CSRF Protection

- Django's CSRF middleware enabled.
- CSRF tokens required for all POST/PUT/DELETE requests from web UI.
- API endpoints use header-based CSRF (X-CSRFToken).

### Rate Limiting

- Vault API: 1000 requests/min per project (configurable via VAULT_API_THROTTLE_RATE).
- Login attempts: Not yet rate-limited; implement in future if needed.

### Audit Logging

- **AuditEvent model:** Append-only, write-once records of vault access.
- **Fields:** principal (API key prefix), action, organization, project, secret_key, timestamp, source_ip, outcome.
- **Access logs:** Can be queried by organization members for compliance.
- **Retention:** See DATA_RETENTION.md.

### Database Security

- **Credentials:** Never hardcoded; loaded from environment variables.
- **Connection pooling:** Enabled in production with health checks to prevent stale connections.
- **Backups:** Encrypted at rest, stored off-site.

### Dependencies

- Managed via requirements.txt (production) and requirements-dev.txt (dev tools).
- Pinned versions to prevent unexpected updates.
- Regular security scans via CI/CD (e.g., Dependabot).
- deprecated: Python 3.13 (actively maintained by PSF).

### Container Security

- **Non-root user:** App runs as unprivileged user (UID 1000) in Docker.
- **Minimal image:** Multi-stage build reduces attack surface (no build tools in runtime image).
- **Read-only root:** Consider enabling read-only root filesystem in orchestration.

## Security Checklist for Production

Before going live:

- [ ] SECRET_KEY set to a cryptographically strong random value.
- [ ] DEBUG=false, DJANGO_ENV=production.
- [ ] ALLOWED_HOSTS configured to your domain(s).
- [ ] Database running with strong password, no public network access.
- [ ] HTTPS enabled with valid TLS certificate.
- [ ] HSTS headers verified (check security headers at securityheaders.com).
- [ ] Backups configured and tested (daily or more frequent).
- [ ] Monitoring & alerting in place (error rates, DB health, API throttling).
- [ ] Firewall restricting DB access to app only.
- [ ] Regular security updates (OS, Python, dependencies).
- [ ] Incident response plan documented and tested.

## Known Limitations

- **Email validation:** In production, configure EMAIL_BACKEND to use SMTP (currently console backend for dev).
- **Account lockout:** No automatic lockout after failed login attempts; implement if needed.
- **Session timeout:** Default Django session timeout (2 weeks); consider reducing for sensitive environments.
- **Webhook security:** Webhooks are HMAC-SHA256 signed; verify signature on receiver.

## Security Contacts

- **Vulnerability reports:** security@doctorhide.com
- **General inquiries:** support@doctorhide.com

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Cryptography.io](https://cryptography.io/) (Fernet, PBKDF2)
- [Django Security](https://docs.djangoproject.com/en/stable/topics/security/)
