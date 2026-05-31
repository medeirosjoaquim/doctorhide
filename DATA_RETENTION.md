# Data Retention & Account Deletion Policy

This document outlines data retention periods, user rights, and account deletion procedures for doctorhide.

## Table of Contents

- [Data Retention Policy](#data-retention-policy)
- [Account Deletion](#account-deletion)
- [User Rights](#user-rights)
- [Data Export](#data-export)
- [Audit & Compliance](#audit--compliance)

## Data Retention Policy

### User Accounts

- **Retention:** User account data (username, email, password hash, TOTP enrollment) is retained for the lifetime of the account.
- **On deletion:** Account and all associated data are deleted immediately (see [Account Deletion](#account-deletion)).

### Projects & Secrets

- **Active secrets:** Retained indefinitely while the account is active.
- **Soft-deleted secrets:** Retained for **30 days** (RECOVERY_WINDOW) after deletion, allowing recovery.
- **Permanent deletion:** After 30 days, soft-deleted secrets are eligible for automatic purge (implementation pending).
- **On account deletion:** All projects and secrets owned by the user are deleted.

### API Keys (Service Accounts)

- **Hashed secrets:** Stored indefinitely. Plaintext is never stored; shown only once at creation.
- **Revoked keys:** Marked with revoked_at timestamp, effectively disabled. Historical record retained.
- **Expiration:** Optional per-key expiration enforced at request time.
- **On account deletion:** All service accounts and their keys are deleted.

### Audit Events

- **Retention:** Append-only records of vault access (principal, action, timestamp, source_ip, outcome).
- **Period:** Retained for **90 days** from creation (implementation pending; currently no auto-purge).
- **Scope:** Audit events are org-scoped; deletion of a user/project does not erase them (project FK uses SET_NULL).
- **Access:** Organization members can query audit logs for compliance.
- **On account deletion:** Audit events referencing deleted projects remain intact for historical integrity.

### Email Verification Tokens

- **Retention:** One-time tokens used during signup for email verification.
- **Expiration:** No hardcoded expiration currently; implement time-based expiration if needed.
- **On deletion:** Deleted with the user account.

### Sessions

- **Default timeout:** 2 weeks (Django default; configurable via SESSION_COOKIE_AGE).
- **Storage:** Stored in database (django.contrib.sessions.backends.db).
- **Cleanup:** Expired sessions can be purged via `python manage.py clearsessions`.

### Backups

- **Database backups:** Retained for **30 days** (operational recommendation).
- **Archive backups:** Long-term retention per compliance requirements (store encrypted, off-site).
- **On account deletion:** Backups older than 30 days may contain deleted user data; implement retention policy separately.

## Account Deletion

### User-Initiated Deletion

Users can delete their account via the web UI:

1. Navigate to **Account Settings**.
2. Scroll to **Danger Zone** > **Delete Account**.
3. Click **Delete Account**.
4. Confirm deletion (no recovery after 30 days).

### What Gets Deleted

- User account (username, email, password hash, TOTP secrets, backup codes).
- All projects owned by the user.
- All secrets in those projects.
- All service accounts and API keys for those projects.
- EmailVerificationToken associated with the account.
- Session tokens for the user.

### What Is Not Deleted

- **Audit events:** Historical records retained for 90 days (per retention policy).
- **Backups:** User data in backups older than 30 days may persist; covered separately by backup retention policy.
- **Webhooks:** Organization-level webhooks are deleted only if the organization itself is deleted (future feature).

### Recovery

Users have a **30-day grace period** to request account recovery after deletion (implementation pending). After 30 days, deletion is permanent.

### Admin-Initiated Deletion

Admins can delete accounts via Django admin:

1. Navigate to **Admin** > **Accounts** > **Users**.
2. Select the user.
3. Click **Delete** (full deletion immediately, no grace period).

## User Rights

### Right to Know

Users can access their personal data via:

- **Account Settings:** View username, email, TOTP enrollment status, created date.
- **Audit Logs:** View organization-level vault audit events (if member).
- **API:** GET /v1/whoami (authenticated endpoint, returns principal info).

### Right to Correction

Users can update:

- **Email address:** Via Account Settings (requires verification).
- **Password:** Via Account Settings.
- **TOTP:** Can re-enroll or reset (admin can force re-enrollment if lost).

### Right to Erasure

Users can:

- **Delete individual secrets:** Via vault UI (soft delete, 30-day recovery window).
- **Delete projects:** Via vault UI (deletes all secrets in the project).
- **Delete account:** Via Account Settings (deletes all data; 30-day recovery pending).

### Right to Portability

Users can export their projects and secrets:

- **Web UI:** Download secrets as JSON (encrypted; decryption happens client-side with user's passphrase).
- **API:** Use vault API endpoints (GET /v1/secrets) to fetch project data.

## Data Export

### Self-Service Export

Users can export secrets from the web UI:

1. Navigate to **Projects** > select a project.
2. Click **Export Secrets** (downloads as .json, encrypted ciphertext).
3. Decrypt client-side using the project passphrase.

### Programmatic Export

Via the vault API (requires valid API key):

```bash
curl -H "Authorization: Bearer dhk_<token>" \
  https://api.doctorhide.com/v1/secrets?project=proj_<id>
```

Response includes encrypted ciphertext; client decrypts with passphrase.

### Format

- **Format:** JSON (secrets as key/value pairs with metadata).
- **Encryption:** Ciphertext is encrypted; plaintext is never sent server-side.
- **Timestamps:** Includes created_at, updated_at for each secret.

## Audit & Compliance

### Audit Logging

All vault access is logged in the `AuditEvent` table:

- **Fields:** principal, action, organization, project, secret_key, timestamp, source_ip, outcome.
- **Queryable:** Via vault API (`GET /v1/audit`); access controlled by organization membership.

### Compliance Queries

Admins can run:

```sql
-- Audit events for the past 90 days
SELECT * FROM vault_auditevent
WHERE timestamp >= NOW() - INTERVAL '90 days'
ORDER BY timestamp DESC;

-- Deleted secrets (soft-deleted, within recovery window)
SELECT * FROM vault_secret
WHERE deleted_at IS NOT NULL
  AND deleted_at > NOW() - INTERVAL '30 days';

-- Failed login attempts (if audit events enabled in accounts app)
SELECT * FROM vault_auditevent
WHERE action = 'login' AND outcome = 'failed';
```

### Retention Enforcement

Recommended automation:

```bash
# Purge audit events older than 90 days (run daily or weekly)
python manage.py shell << EOF
from django.utils import timezone
from vault.models import AuditEvent
cutoff = timezone.now() - timezone.timedelta(days=90)
AuditEvent.objects.filter(timestamp__lt=cutoff).delete()
EOF

# Purge soft-deleted secrets older than 30 days (run daily)
python manage.py shell << EOF
from django.utils import timezone
from vault.models import Secret
cutoff = timezone.now() - timezone.timedelta(days=30)
Secret.objects.filter(deleted_at__lt=cutoff).delete()
EOF

# Purge expired sessions (built-in Django command)
python manage.py clearsessions
```

### GDPR / Privacy Compliance

- **Data Processing Agreement (DPA):** If applicable, ensure DPA is in place with users or their organizations.
- **Right to Erasure:** Implemented via account deletion (see [Account Deletion](#account-deletion)).
- **Data Minimization:** Only essential data collected (username, email, TOTP secret, audit logs).
- **Purpose Limitation:** Data used only for authentication, encryption, and audit trails.
- **Consent:** Users consent to Terms of Service at signup.

## Technical Implementation Notes

### Soft Deletes

Secrets use a `deleted_at` timestamp (nullable) to implement soft deletes:

- **Soft-deleted:** deleted_at is not NULL.
- **Active:** deleted_at is NULL.
- **Queries:** Exclude soft-deleted secrets: `Secret.objects.filter(deleted_at__isnull=True)`.
- **Recovery:** `secret.restore()` clears deleted_at within the recovery window.

### Cascading Deletes

- **User deletion:** CASCADE -> Projects, Secrets, APIKeys, EmailVerificationToken.
- **Project deletion:** CASCADE -> Secrets, SecretVersions, ProjectAPIKeys.
- **Organization deletion:** CASCADE -> Projects, Webhooks, AuditEvents.

### Backups and Deleted Data

Database backups are taken before `DELETE` statements. Older backups (>30 days) may contain deleted user data. Consider:

- Separate encryption key for backups.
- Off-site storage with restricted access.
- Policy to purge backups older than retention period.
- Secure deletion (DBAN, cryptographic erasure) when decommissioning storage.

## Questions or Requests

Users can submit data access, correction, or deletion requests to:

- **Email:** privacy@doctorhide.com
- **Web Form:** Via Account Settings or contact page.

We aim to respond within **30 days** (or per local privacy law requirements).
